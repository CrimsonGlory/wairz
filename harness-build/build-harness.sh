#!/bin/bash
# build-harness.sh — cross-compile a fuzzing harness that links a firmware
# shared library, for the firmware's architecture, against the firmware's own
# libraries as the link sysroot.
#
# Inputs (env):
#   WZ_ARCH   wairz arch key (armhf|armel|aarch64|mips|mipsel)
#   WZ_SRC    path to the harness C source (under /carved)
#   WZ_LIB    path to the target shared library (under /firmware)
#   WZ_OUT    output ELF path (under /carved)
#
# The firmware rootfs is mounted read-only at /firmware; /carved is writable.
# Prints a build report; exits non-zero on failure.
set -u

ARCH="${WZ_ARCH:-}"
SRC="${WZ_SRC:-}"
LIB="${WZ_LIB:-}"
OUT="${WZ_OUT:-}"

fail() { echo "BUILD_ERROR: $*" >&2; exit 1; }

[ -n "$ARCH" ] && [ -n "$SRC" ] && [ -n "$LIB" ] && [ -n "$OUT" ] \
    || fail "missing one of WZ_ARCH/WZ_SRC/WZ_LIB/WZ_OUT"
[ -f "$SRC" ] || fail "harness source not found: $SRC"
[ -f "$LIB" ] || fail "target library not found: $LIB"

TCDIR="/opt/toolchains/$ARCH"
[ -d "$TCDIR" ] || fail "no toolchain bundled for arch '$ARCH' (have: $(ls /opt/toolchains 2>/dev/null | tr '\n' ' '))"

# The Bootlin toolchains ship a "<triple>-gcc" plus a short "<arch>-linux-gcc"
# wrapper; pick the plain gcc driver (exclude gcc-ar/gcc-nm/gcc-ranugcc etc.).
GCC=$(ls "$TCDIR"/bin/*-gcc 2>/dev/null | grep -vE 'gcc-(ar|nm|ranlib)' | head -1)
[ -n "$GCC" ] && [ -x "$GCC" ] || fail "no gcc found under $TCDIR/bin"
echo "Toolchain: $($GCC --version 2>/dev/null | head -1)"

LIBDIR=$(dirname "$LIB")
LIBNAME=$(basename "$LIB")

# Firmware library search paths for transitive (NEEDED) resolution at link time.
RPATH_ARGS=""
for d in /firmware/lib /firmware/usr/lib /firmware/usr/local/lib "$LIBDIR"; do
    [ -d "$d" ] && RPATH_ARGS="$RPATH_ARGS -L$d -Wl,-rpath-link,$d"
done

mkdir -p "$(dirname "$OUT")"

echo "Compiling harness: arch=$ARCH lib=$LIBNAME"
set -x
"$GCC" -O1 -g "$SRC" -o "$OUT" \
    -L"$LIBDIR" -l:"$LIBNAME" \
    $RPATH_ARGS \
    -Wl,--allow-shlib-undefined \
    2> /carved/.harness_build.log
rc=$?
set +x

if [ $rc -ne 0 ]; then
    echo "=== compiler/linker output ==="
    cat /carved/.harness_build.log 2>/dev/null
    fail "cross-compile failed (rc=$rc)"
fi

# Report what we produced. The max GLIBC symbol version must be low enough for
# the firmware libc; flag it so the caller can warn.
READELF=$(ls "$TCDIR"/bin/*-readelf 2>/dev/null | head -1)
echo "BUILD_OK: $OUT"
echo "FILE: $(file -b "$OUT" 2>/dev/null)"
if [ -n "$READELF" ]; then
    MAXG=$("$READELF" -W --version-info "$OUT" 2>/dev/null \
        | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -1)
    echo "GLIBC_MAX: ${MAXG:-none}"
    echo "NEEDED: $("$READELF" -d "$OUT" 2>/dev/null | grep NEEDED \
        | grep -oE '\[[^]]+\]' | tr -d '[]' | tr '\n' ' ')"
    # Whether PIE — AFL_QEMU_PERSISTENT_ADDR uses absolute addrs for ET_EXEC,
    # base+offset for ET_DYN (PIE).
    echo "ELF_TYPE: $("$READELF" -h "$OUT" 2>/dev/null | awk -F: '/Type:/{print $2}' | tr -d ' ' | head -1)"
fi
NM=$(ls "$TCDIR"/bin/*-nm 2>/dev/null | head -1)
if [ -n "$NM" ]; then
    # Entry addresses for optional QEMU persistent-mode fuzzing
    # (AFL_QEMU_PERSISTENT_ADDR). harness_one wraps a single call to the target.
    for sym in harness_one main; do
        addr=$("$NM" "$OUT" 2>/dev/null | awk -v s="$sym" '$3==s{print $1}' | head -1)
        [ -n "$addr" ] && echo "ADDR_${sym}: 0x${addr}"
    done
fi
exit 0
