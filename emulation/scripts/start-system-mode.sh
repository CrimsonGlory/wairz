#!/bin/bash
# start-system-mode.sh — Boot firmware via QEMU system-mode
#
# Usage: start-system-mode.sh <arch> <rootfs_path> <kernel_path> [port_forwards]
#
# This script boots a full system-mode QEMU instance with the firmware
# filesystem as the root. Serial console is exposed via socat on a Unix socket.

set -euo pipefail

ARCH="$1"
ROOTFS="$2"
KERNEL="$3"
PORT_FORWARDS="$4"  # comma-separated host:guest pairs, e.g., "8080:80,2222:22"
INITRD="$5"         # optional path to initramfs/initrd image
INIT_PATH="$6"      # optional init binary override (e.g., /bin/sh)

LOG="/tmp/qemu-system.log"
SERIAL_SOCK="/tmp/qemu-serial.sock"
SERIAL_LOG="/tmp/qemu-serial.log"
# Dedicated command channel (feedback #6): an isolated serial/virtio-console
# device carries run_command_in_emulation I/O, separate from the kernel
# console. Wired up only when WAIRZ_CMD_CHANNEL is set by the backend.
CMD_SOCK="/tmp/qemu-cmd.sock"
ROOTFS_IMG="/tmp/rootfs.ext4"

# Always create the log file immediately so diagnostics are available
exec > >(tee -a "$LOG") 2>&1

echo "=== QEMU System-Mode Start ==="
echo "Time: $(date -u 2>/dev/null || echo unknown)"
echo "Arch: $ARCH"
echo "Rootfs: $ROOTFS"
echo "Kernel: $KERNEL"
echo "Port forwards: $PORT_FORWARDS"

if [ -z "$ARCH" ] || [ -z "$ROOTFS" ] || [ -z "$KERNEL" ]; then
    echo "ERROR: Usage: start-system-mode.sh <arch> <rootfs_path> <kernel_path> [port_forwards]"
    exit 1
fi

if [ ! -f "$KERNEL" ]; then
    echo "ERROR: Kernel not found: $KERNEL"
    echo "System-mode emulation requires a pre-built kernel for the target architecture."
    echo "Upload a kernel via the Kernel Manager or place one in emulation/kernels/."
    exit 1
fi

if [ ! -d "$ROOTFS" ]; then
    echo "ERROR: Rootfs directory not found: $ROOTFS"
    exit 1
fi

echo "Kernel file size: $(wc -c < "$KERNEL") bytes"

# Suppress ALSA audio warnings from QEMU
export QEMU_AUDIO_DRV=none

# Validate kernel file format before proceeding with slow ext4 image creation
KERNEL_MAGIC=$(xxd -p -l 4 "$KERNEL" 2>/dev/null)
KERNEL_VALID=0
case "$KERNEL_MAGIC" in
    7f454c46) echo "Kernel format: ELF"; KERNEL_VALID=1 ;;           # ELF
    27051956) echo "Kernel format: U-Boot uImage"; KERNEL_VALID=1 ;; # uImage
    1f8b*)    echo "Kernel format: gzip-compressed"; KERNEL_VALID=1 ;; # gzip
    5d0000*)  echo "Kernel format: LZMA-compressed"; KERNEL_VALID=1 ;; # LZMA
esac
# Check x86 bzImage magic at offset 0x202
if [ "$KERNEL_VALID" -eq 0 ]; then
    X86_MAGIC=$(xxd -p -l 4 -s 0x202 "$KERNEL" 2>/dev/null)
    if [ "$X86_MAGIC" = "48647253" ]; then
        echo "Kernel format: x86 bzImage"
        KERNEL_VALID=1
    fi
fi
# Check ARM zImage magic at offset 0x24
if [ "$KERNEL_VALID" -eq 0 ]; then
    ARM_MAGIC=$(xxd -p -l 4 -s 0x24 "$KERNEL" 2>/dev/null)
    if [ "$ARM_MAGIC" = "18286f01" ]; then
        echo "Kernel format: ARM zImage"
        KERNEL_VALID=1
    fi
fi
if [ "$KERNEL_VALID" -eq 0 ]; then
    echo "ERROR: Unrecognized kernel format (magic: $KERNEL_MAGIC)"
    echo "The file does not appear to be a valid kernel image (ELF/uImage/zImage/gzip/LZMA)."
    echo "This may be a filesystem image or raw data extracted by binwalk."
    echo "Upload a proper QEMU-compatible kernel via the Kernel Manager."
    exit 1
fi

# Decompress kernel if gzip/LZMA compressed — QEMU may not handle compressed
# kernels directly (especially for aarch64 Image format)
case "$KERNEL_MAGIC" in
    1f8b*)
        echo "Decompressing gzip-compressed kernel..."
        KERNEL_DECOMPRESSED="/tmp/kernel_decompressed"
        if gunzip -c "$KERNEL" > "$KERNEL_DECOMPRESSED" 2>&1; then
            KERNEL="$KERNEL_DECOMPRESSED"
            echo "Decompressed kernel: $(wc -c < "$KERNEL") bytes"
        else
            echo "WARNING: Failed to decompress kernel, trying as-is"
        fi
        ;;
    5d0000*)
        echo "Decompressing LZMA-compressed kernel..."
        KERNEL_DECOMPRESSED="/tmp/kernel_decompressed"
        if unlzma -c "$KERNEL" > "$KERNEL_DECOMPRESSED" 2>/dev/null || \
           lzma -dc "$KERNEL" > "$KERNEL_DECOMPRESSED" 2>/dev/null; then
            KERNEL="$KERNEL_DECOMPRESSED"
            echo "Decompressed kernel: $(wc -c < "$KERNEL") bytes"
        else
            echo "WARNING: Failed to decompress kernel, trying as-is"
        fi
        ;;
esac

# Clean up stale files from previous runs
rm -f "$SERIAL_SOCK" "$SERIAL_LOG" "$CMD_SOCK" "$ROOTFS_IMG"

# Create a temporary ext4 image sized to fit the rootfs (2x content + 256MB headroom)
ROOTFS_MB=$(du -sm "$ROOTFS" 2>/dev/null | cut -f1)
ROOTFS_MB=${ROOTFS_MB:-0}
IMG_MB=$(( ROOTFS_MB * 2 + 256 ))
INODE_COUNT=$(( $(find "$ROOTFS" 2>/dev/null | wc -l) * 2 + 4096 ))
echo "Creating ext4 rootfs image (${IMG_MB} MB, rootfs: ${ROOTFS_MB} MB, inodes: ${INODE_COUNT})..."
dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count="$IMG_MB" 2>/dev/null
if ! mkfs.ext4 -q -N "$INODE_COUNT" -d "$ROOTFS" "$ROOTFS_IMG" 2>&1; then
    echo "WARNING: mkfs.ext4 -d failed — falling back to empty image; init script will be missing and kernel will panic."
    mkfs.ext4 -q "$ROOTFS_IMG" 2>&1 || true
fi
echo "Rootfs image created: $(wc -c < "$ROOTFS_IMG") bytes"

# Select QEMU binary, machine type, drive interface, and root device
# Different machine types expose block devices differently:
#   - versatilepb (ARM): IDE → /dev/sda
#   - virt (aarch64): virtio only → /dev/vda
#   - malta (MIPS): IDE → /dev/sda
#   - pc (x86): IDE → /dev/sda
case "$ARCH" in
    arm|armhf|armel)
        QEMU_BIN="qemu-system-arm"
        MACHINE="versatilepb"
        CONSOLE="ttyAMA0"
        DRIVE_IF=""
        ROOT_DEV="/dev/sda"
        CPU_ARGS=""
        GUEST_RAM="256"  # versatilepb max is 256MB
        NIC_DEVICE="smc91c111"  # on-board SysBus NIC of versatilepb
        NIC_ONBOARD="1"  # not a pluggable -device; must use unified -nic syntax
        ;;
    aarch64|arm64)
        QEMU_BIN="qemu-system-aarch64"
        MACHINE="virt"
        CONSOLE="ttyAMA0"
        DRIVE_IF=",if=virtio"
        ROOT_DEV="/dev/vda"
        CPU_ARGS="-cpu cortex-a57"
        GUEST_RAM="512"
        NIC_DEVICE="virtio-net-pci"  # standard for virt machine
        ;;
    mips|mipsbe)
        QEMU_BIN="qemu-system-mips"
        MACHINE="malta"
        CONSOLE="ttyS0"
        DRIVE_IF=""
        ROOT_DEV="/dev/sda"
        CPU_ARGS="-cpu 34Kf"  # MIPS32r2 + DSP + FPU (4Kc default only supports r1)
        GUEST_RAM="256"  # malta max is 256MB
        NIC_DEVICE="pcnet"  # Malta native NIC; pcnet32+mii modules loaded by initramfs
        ;;
    mipsel|mipsle)
        QEMU_BIN="qemu-system-mipsel"
        MACHINE="malta"
        CONSOLE="ttyS0"
        DRIVE_IF=""
        ROOT_DEV="/dev/sda"
        CPU_ARGS="-cpu 34Kf"  # MIPS32r2 + DSP + FPU (4Kc default only supports r1)
        GUEST_RAM="256"  # malta max is 256MB
        NIC_DEVICE="pcnet"  # Malta native NIC; pcnet32+mii modules loaded by initramfs
        ;;
    x86|i386|i686)
        QEMU_BIN="qemu-system-i386"
        MACHINE="pc"
        CONSOLE="ttyS0"
        DRIVE_IF=""
        ROOT_DEV="/dev/sda"
        CPU_ARGS=""
        GUEST_RAM="512"
        NIC_DEVICE="e1000"  # built into most x86 kernels
        ;;
    x86_64|amd64)
        QEMU_BIN="qemu-system-x86_64"
        MACHINE="pc"
        CONSOLE="ttyS0"
        DRIVE_IF=""
        ROOT_DEV="/dev/sda"
        CPU_ARGS=""
        GUEST_RAM="512"
        NIC_DEVICE="e1000"  # built into most x86 kernels
        ;;
    *)
        echo "ERROR: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# ── Agent-supplied overrides (optional) ───────────────────────────────────────
# Every per-arch default selected above is overridable via an environment
# variable set by the emulation harness (start_emulation's cpu/machine/mem/...
# parameters). This makes system-mode bring-up iterable without code changes:
# the agent can sweep machine/CPU/console/root-device/initrd/cmdline the same
# way a human turns the qemu-system-* knobs. An unset variable keeps the
# auto-selected default.
[ -n "$WAIRZ_MACHINE" ]  && { echo "Override: machine -> $WAIRZ_MACHINE"; MACHINE="$WAIRZ_MACHINE"; }
[ -n "$WAIRZ_CPU" ]      && { echo "Override: cpu -> $WAIRZ_CPU"; CPU_ARGS="-cpu $WAIRZ_CPU"; }
[ -n "$WAIRZ_MEM" ]      && { echo "Override: mem -> ${WAIRZ_MEM} MB"; GUEST_RAM="$WAIRZ_MEM"; }
[ -n "$WAIRZ_ROOT_DEV" ] && { echo "Override: root device -> $WAIRZ_ROOT_DEV"; ROOT_DEV="$WAIRZ_ROOT_DEV"; }
if [ -n "$WAIRZ_DRIVE_IF" ]; then
    echo "Override: drive interface -> $WAIRZ_DRIVE_IF"
    case "$WAIRZ_DRIVE_IF" in
        ide|default) DRIVE_IF="" ;;          # bare -drive defaults to IDE
        *)           DRIVE_IF=",if=$WAIRZ_DRIVE_IF" ;;
    esac
fi
SMP_ARGS=""
[ -n "$WAIRZ_SMP" ] && { echo "Override: smp -> $WAIRZ_SMP"; SMP_ARGS="-smp $WAIRZ_SMP"; }
# Raw passthrough — anything not modeled above. Word-split intentionally so
# multiple args ("-foo bar -baz") reach QEMU as separate tokens.
QEMU_EXTRA_ARGS="$WAIRZ_QEMU_EXTRA"
[ -n "$QEMU_EXTRA_ARGS" ] && echo "Extra QEMU args: $QEMU_EXTRA_ARGS"

# ── NIC model is a property of the MACHINE, not the CPU arch ───────────────────
# The per-arch defaults above picked a NIC for each arch's DEFAULT machine, but
# the agent can override `machine` (e.g. arm -> virt). The NIC controller lives
# on the machine: versatilepb has an on-board smc91c111, virt expects a
# pluggable virtio-net, malta a pcnet, pc an e1000. Re-derive it from the
# EFFECTIVE machine so overriding `machine` doesn't leave a NIC the board can't
# host (e.g. "Unsupported NIC model: smc91c111" on virt). Unknown/custom
# machines keep the arch-derived guess. NIC_ONBOARD marks the on-board SysBus
# NICs that must use the unified `-nic` syntax instead of `-device`.
case "$MACHINE" in
    versatilepb) NIC_DEVICE="smc91c111";        NIC_ONBOARD="1" ;;
    virt)        NIC_DEVICE="virtio-net-device"; NIC_ONBOARD="0" ;;
    malta)       NIC_DEVICE="pcnet";             NIC_ONBOARD="0" ;;
    pc|q35)      NIC_DEVICE="e1000";             NIC_ONBOARD="0" ;;
    *) : ;;  # keep the arch-derived NIC_DEVICE/NIC_ONBOARD as a best guess
esac
# Explicit agent override always wins. smc91c111/lan9118 are the on-board
# SysBus models; everything else is treated as a pluggable -device.
if [ -n "$WAIRZ_NIC_MODEL" ]; then
    echo "Override: nic model -> $WAIRZ_NIC_MODEL"
    NIC_DEVICE="$WAIRZ_NIC_MODEL"
    case "$WAIRZ_NIC_MODEL" in
        smc91c111|lan9118) NIC_ONBOARD="1" ;;
        *)                 NIC_ONBOARD="0" ;;
    esac
fi

# Build networking. The NIC attachment syntax depends on whether the machine's
# NIC is an on-board (SysBus) controller or a pluggable (PCI) device:
#   - versatilepb's smc91c111 is auto-instantiated by the machine and is NOT a
#     user-creatable -device — `-device smc91c111` fails with "Parameter
#     'driver' expects a pluggable device type" and QEMU exits before boot. It
#     must be wired up via the unified `-nic user,model=smc91c111,...` syntax.
#   - virt/malta/pc NICs (virtio-net-pci, pcnet, e1000) are pluggable PCI
#     devices, so the split `-netdev`/`-device` form works.
# We accumulate the SLiRP user-net options (incl. hostfwd port-forwards) once
# and attach them via whichever syntax the machine requires.
#
# Port forwarding: QEMU SLiRP hostfwd only reliably handles connections from
# 127.0.0.1, but Docker port proxies forward from the container's bridge IP.
# Workaround: QEMU hostfwd listens on 127.0.0.1 with offset ports (+10000),
# and socat relays on the original ports forward via localhost to QEMU.
USERNET_OPTS=""
RELAY_PIDS=""
if [ -n "$PORT_FORWARDS" ]; then
    IFS=',' read -ra PAIRS <<< "$PORT_FORWARDS"
    for pair in "${PAIRS[@]}"; do
        host_port="${pair%%:*}"
        guest_port="${pair##*:}"
        relay_port=$((host_port + 10000))
        USERNET_OPTS="${USERNET_OPTS},hostfwd=tcp:127.0.0.1:${relay_port}-:${guest_port}"
        # Start socat relay: listens on all interfaces, forwards to QEMU via localhost
        socat TCP-LISTEN:${host_port},bind=0.0.0.0,fork,reuseaddr \
              TCP:127.0.0.1:${relay_port} &
        RELAY_PIDS="$RELAY_PIDS $!"
        echo "Port relay: 0.0.0.0:${host_port} → 127.0.0.1:${relay_port} → guest:${guest_port}"
    done
fi
# Clean up socat relay processes on exit
if [ -n "$RELAY_PIDS" ]; then
    trap 'kill $RELAY_PIDS 2>/dev/null' EXIT
fi
NET_ARGS="-device ${NIC_DEVICE},netdev=net0 -netdev ${NETDEV_ARGS}"

# Verify QEMU binary exists
if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
    echo "ERROR: $QEMU_BIN not found in PATH"
    exit 1
fi

echo "Starting: $QEMU_BIN -M $MACHINE $CPU_ARGS"
echo "Serial console: $SERIAL_SOCK"
echo "Serial log: $SERIAL_LOG"
echo "Drive interface: ${DRIVE_IF:-default}"
# Build optional initrd argument
INITRD_ARGS=""
if [ -n "$INITRD" ] && [ -f "$INITRD" ]; then
    echo "Initrd: $INITRD ($(wc -c < "$INITRD") bytes)"
    INITRD_ARGS="-initrd $INITRD"
else
    echo "Initrd: none"
fi

# Build optional device-tree argument (WAIRZ_DTB points at a dtb copied into the
# container). DT-only kernels (e.g. the bundled buster RPi kernel) fail with
# "invalid dtb and unrecognized/unsupported machine ID" without it.
DTB_ARGS=""
if [ -n "$WAIRZ_DTB" ] && [ -f "$WAIRZ_DTB" ]; then
    echo "DTB: $WAIRZ_DTB ($(wc -c < "$WAIRZ_DTB") bytes)"
    DTB_ARGS="-dtb $WAIRZ_DTB"
else
    echo "DTB: none"
fi

# Extra drives (WAIRZ_EXTRA_DRIVES = comma-separated container image paths).
# Attached after the root disk on the same bus, so the guest sees them as the
# next device letters (virtio: vdb,vdc…; ide: sdb,sdc…). Used for devices whose
# config/data lives on a separate flash/MMC partition carved from the raw image.
EXTRA_DRIVE_ARGS=""
if [ -n "$WAIRZ_EXTRA_DRIVES" ]; then
    IFS=',' read -ra _XDRIVES <<< "$WAIRZ_EXTRA_DRIVES"
    for _xd in "${_XDRIVES[@]}"; do
        if [ -f "$_xd" ]; then
            EXTRA_DRIVE_ARGS="$EXTRA_DRIVE_ARGS -drive file=$_xd,format=raw${DRIVE_IF}"
            echo "Extra drive: $_xd ($(wc -c < "$_xd") bytes, if=${DRIVE_IF:-ide})"
        else
            echo "WARNING: extra drive not found, skipping: $_xd"
        fi
    done
fi

# Dedicated command channel (feedback #6). The backend sets WAIRZ_CMD_CHANNEL
# to the transport for this machine: "virtio" (virtio-console → /dev/hvc0, used
# on -M virt) or "serial" (a 2nd UART → /dev/ttyAMA1 or /dev/ttyS1). Both back
# onto $CMD_SOCK, which serial-exec.sh prefers over the noisy console socket.
CMD_CHANNEL_ARGS=""
case "${WAIRZ_CMD_CHANNEL:-}" in
    virtio)
        CMD_CHANNEL_ARGS="-chardev socket,id=charcmd0,server=on,wait=off,path=${CMD_SOCK} -device virtio-serial-device -device virtconsole,chardev=charcmd0"
        echo "Command channel: virtio-console (/dev/hvc0) on $CMD_SOCK"
        ;;
    serial)
        # Second -serial → guest's second UART (serial1). Console stays serial0.
        CMD_CHANNEL_ARGS="-chardev socket,id=charcmd0,server=on,wait=off,path=${CMD_SOCK} -serial chardev:charcmd0"
        echo "Command channel: 2nd UART on $CMD_SOCK"
        ;;
    *)
        echo "Command channel: none (run_command_in_emulation uses the console)"
        ;;
esac

# Build kernel append string
APPEND_ARGS="root=$ROOT_DEV rw console=$CONSOLE panic=0"
if [ -n "$INIT_PATH" ]; then
    APPEND_ARGS="$APPEND_ARGS init=$INIT_PATH"
    echo "Init override: $INIT_PATH"
fi
# Agent-supplied extra kernel cmdline (rootwait, custom console=, panic=N, etc.)
# is appended last so it wins where the kernel takes the final value.
if [ -n "$WAIRZ_KERNEL_APPEND" ]; then
    APPEND_ARGS="$APPEND_ARGS $WAIRZ_KERNEL_APPEND"
    echo "Extra kernel append: $WAIRZ_KERNEL_APPEND"
fi
echo "Kernel append: $APPEND_ARGS"

# Launch QEMU
# -nodefaults: suppress audio/USB/etc warnings
# -no-reboot: exit instead of rebooting (prevents infinite loops)
# -gdb tcp::1234: expose GDB stub for remote debugging
# Use the explicit chardev form so we can attach `logfile=` — that gives us
# a passive copy of every byte that crosses the serial port, even when no
# socat client is connected. Without it, kernel-boot output (incl. panics)
# is dropped on the floor and only `run_command_in_emulation` sees it.
SERIAL_CHARDEV="socket,id=charserial0,server=on,wait=off,path=${SERIAL_SOCK},logfile=${SERIAL_LOG},logappend=off"

exec "$QEMU_BIN" \
    -M "$MACHINE" \
    $CPU_ARGS \
    $SMP_ARGS \
    -m "${GUEST_RAM:-256}" \
    -nographic \
    -nodefaults \
    -no-reboot \
    -chardev "$SERIAL_CHARDEV" \
    -serial chardev:charserial0 \
    $CMD_CHANNEL_ARGS \
    -monitor none \
    -gdb tcp::1234 \
    -kernel "$KERNEL" \
    $INITRD_ARGS \
    $DTB_ARGS \
    -drive "file=$ROOTFS_IMG,format=raw${DRIVE_IF}" \
    $EXTRA_DRIVE_ARGS \
    -append "$APPEND_ARGS" \
    $NET_ARGS \
    $QEMU_EXTRA_ARGS
