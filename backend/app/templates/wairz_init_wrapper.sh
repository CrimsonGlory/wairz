@@SHEBANG@@
# Wairz emulation init wrapper
# Auto-configures the emulated environment before starting firmware init

# Bring busybox applets into PATH on rootfs layouts where the binaries
# live somewhere other than /bin and /sbin (e.g. /bin/busybox/{bin,sbin}).
# Without this, mount/ifconfig/etc. below would fail with "not found".
export PATH="/bin:/sbin:/usr/bin:/usr/sbin:/bin/busybox/bin:/bin/busybox/sbin:$PATH"

echo "[wairz] Init wrapper starting..."

# Fix broken symlinks: binwalk converts out-of-tree symlinks to /dev/null.
# Many embedded firmware images have /etc, /home, /webroot etc. pointing to
# tmpfs paths (/var/etc, /var/home, /var/webroot) that binwalk can't resolve.
# Fix them here so the firmware boots properly.
for lnk in /etc /home /root /webroot /debug; do
    if [ -L "$lnk" ] && [ "$(readlink "$lnk")" = "/dev/null" ]; then
        rm -f "$lnk"
        mkdir -p "$lnk"
        echo "[wairz] Fixed broken symlink: $lnk"
    fi
done
# Populate directories from their read-only counterparts (e.g. /etc_ro -> /etc)
for rodir in /etc_ro /webroot_ro; do
    target="${rodir%_ro}"
    if [ -d "$rodir" ] && [ -d "$target" ]; then
        cp -a "$rodir"/* "$target"/ 2>/dev/null || true
        echo "[wairz] Populated $target from $rodir"
    fi
done
# Also fix broken /dev/null symlinks inside key directories
for dir in /etc /webroot /webroot_ro /home /root; do
    [ -d "$dir" ] || continue
    for f in "$dir"/*; do
        [ -L "$f" ] && [ "$(readlink "$f")" = "/dev/null" ] && rm -f "$f" && \
            echo "[wairz] Removed broken symlink: $f"
    done
done

# Enable passwordless root login for serial console access.
# Fix both /etc/ and /etc_ro/ since firmware rcS typically copies /etc_ro/* -> /etc/.
for d in /etc /etc_ro; do
    [ -f "$d/passwd" ] && sed -i 's|^root:[^:]*:|root::|' "$d/passwd" 2>/dev/null
    [ -f "$d/shadow" ] && sed -i 's|^root:[^:]*:|root::|' "$d/shadow" 2>/dev/null
    [ -f "$d/inittab" ] && sed -i 's|/sbin/sulogin|/bin/sh -l|g' "$d/inittab" 2>/dev/null
done
echo "[wairz] Fixed root password and inittab (sulogin -> sh)"

# Mount essential filesystems
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
[ -c /dev/null ] || mount -t devtmpfs devtmpfs /dev 2>/dev/null
mkdir -p /tmp /var/run 2>/dev/null
mount -t tmpfs tmpfs /tmp 2>/dev/null
mount -t tmpfs tmpfs /var/run 2>/dev/null

# Configure networking (QEMU user-mode networking uses 10.0.2.0/24)
# Wait briefly for NIC driver to initialize
sleep 1
if command -v ifconfig >/dev/null 2>&1; then
    ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up 2>/dev/null
    route add default gw 10.0.2.2 2>/dev/null
elif command -v ip >/dev/null 2>&1; then
    ip addr add 10.0.2.15/24 dev eth0 2>/dev/null
    ip link set eth0 up 2>/dev/null
    ip route add default via 10.0.2.2 2>/dev/null
fi

# Verify networking
if command -v ifconfig >/dev/null 2>&1; then
    echo "[wairz] Network: $(ifconfig eth0 2>/dev/null | grep 'inet ' || echo 'not configured')"
fi
@@PRE_INIT_BLOCK@@

# Enable core dumps for crash analysis
ulimit -c unlimited 2>/dev/null || true
mkdir -p /tmp/cores 2>/dev/null
if [ -d /proc/sys/kernel ]; then
    echo "/tmp/cores/core.%e.%p" > /proc/sys/kernel/core_pattern 2>/dev/null || true
fi
echo "[wairz] Core dumps enabled: /tmp/cores/core.<binary>.<pid>"

@@STUB_BLOCK@@

echo "[wairz] Starting firmware init..."
@@EXEC_LINE@@
