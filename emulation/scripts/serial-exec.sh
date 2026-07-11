#!/bin/bash
# serial-exec.sh — Execute a command via a QEMU serial channel and capture output
#
# Usage: serial-exec.sh <command> [timeout_seconds]
#
# Connects to a QEMU serial Unix socket, sends the command wrapped in unique
# markers, captures output between markers, and prints the result. Exit code
# reflects the guest command's exit code (or 124 for timeout).
#
# Channel selection (feedback #6): prefers the dedicated command channel
# (/tmp/qemu-cmd.sock) — an isolated serial/virtio-console device with a
# persistent echo-disabled shell, free of kernel printk / syslog / getty noise
# that corrupts marker extraction on the shared console. Falls back to the
# console socket (/tmp/qemu-serial.sock) when the command channel is absent or
# doesn't respond (boards/kernels without a usable second device).
#
# The connection trick: `echo cmd | socat` closes on EOF before output can be
# read, so we keep the connection open with a background sleep, watch for the
# end marker, then extract.

set -u

CMD="$1"
TIMEOUT="${2:-30}"

CMD_SOCK="/tmp/qemu-cmd.sock"
CONSOLE_SOCK="/tmp/qemu-serial.sock"

# Unique markers for this execution (alphanumeric only for shell safety).
MK="WZE${$}$(date +%s)"
START_MK="WAIRZ_START_${MK}"
END_MK="WAIRZ_END_${MK}_"

# For long commands (>200 chars), base64-encode to avoid serial line-buffer
# truncation. The guest decodes and executes via sh.
if [ ${#CMD} -gt 200 ]; then
    B64=$(echo "$CMD" | base64 -w 0)
    INNER_CMD="echo ${B64}|base64 -d|sh"
else
    INNER_CMD="$CMD"
fi

# Combine stdout+stderr (serial is a single stream); append exit code to the
# end marker for extraction. The bare `echo` before the end marker guards it
# onto its own line — without it, command output lacking a trailing newline
# (e.g. `head -c N`) would share a line with the end marker and be dropped by
# the awk extraction.
WRAPPED="echo ${START_MK}; (${INNER_CMD}) 2>&1; echo; echo ${END_MK}\$?"

# Globals set by run_on_sock().
OUTPUT=""
EXIT_CODE=1
FOUND=0

# run_on_sock <socket-path> [reset] — send WRAPPED to the socket, capture output.
# reset=1 (console): send Ctrl-C first to clear a stuck foreground process and
# get a fresh prompt. reset=0 (dedicated command channel): the channel serves a
# clean non-interactive shell, so skip Ctrl-C (which would needlessly kill and
# respawn it) and just send the command.
run_on_sock() {
    sock="$1"
    reset="${2:-1}"
    raw="/tmp/_sout_$$_$(basename "$sock")"
    rm -f "$raw"

    {
        sleep 0.3          # wait for socat connection to establish
        if [ "$reset" = "1" ]; then
            printf '\x03'  # Ctrl-C to clear any stuck foreground process
            sleep 0.3
            printf '\n'    # fresh prompt
            sleep 0.3
        fi
        printf '%s\n' "$WRAPPED"
        sleep "$TIMEOUT"   # keep the connection alive until timeout
    } | timeout "$((TIMEOUT + 3))" socat -T"$((TIMEOUT + 2))" - "UNIX-CONNECT:$sock" > "$raw" 2>/dev/null &
    socat_pid=$!

    # Watch for the end marker so we can stop early instead of waiting the full
    # timeout.
    deadline=$((SECONDS + TIMEOUT + 1))
    FOUND=0
    while [ $SECONDS -lt $deadline ]; do
        if [ -f "$raw" ] && grep -qF "$END_MK" "$raw" 2>/dev/null; then
            FOUND=1
            sleep 0.2  # let final bytes flush
            kill $socat_pid 2>/dev/null || true
            break
        fi
        sleep 0.2
    done
    wait $socat_pid 2>/dev/null || true

    if [ "$FOUND" -eq 0 ]; then
        rm -f "$raw"
        return 1
    fi

    # Extract output between markers. The console channel echoes our command,
    # so START_MK can appear twice; awk resets on each match. The dedicated
    # command channel has echo disabled, so it appears once — same handling.
    OUTPUT=$(awk "/${START_MK}/{found=1; next} /${END_MK}/{exit} found{print}" "$raw")
    OUTPUT=$(printf '%s' "$OUTPUT" | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\x1b\][^\x07]*\x07//g; s/\r//g')
    # Strip the trailing blank line the end-marker guard adds, then drop any
    # leading/trailing blank-only lines.
    OUTPUT=$(printf '%s\n' "$OUTPUT" | sed -e '${/^$/d}')
    # Extract the exit code from the end-marker line. Strip CRs first (the tty
    # maps \n→\r\n) so the trailing digit isn't masked.
    EXIT_CODE=$(tr -d '\r' < "$raw" | grep -o "${END_MK}[0-9][0-9]*" | head -1 | sed "s/${END_MK}//")
    EXIT_CODE="${EXIT_CODE:-1}"
    rm -f "$raw"
    return 0
}

# Prefer the dedicated command channel (no reset); fall back to the console.
if [ -S "$CMD_SOCK" ]; then
    run_on_sock "$CMD_SOCK" 0
    if [ "$FOUND" -eq 0 ] && [ -S "$CONSOLE_SOCK" ]; then
        # Command channel socket exists but no shell answered (kernel lacked the
        # device). Fall back to the console WITHOUT the Ctrl-C reset: a stray ^C
        # on this shared socket interrupts whatever an interactive analyst (the
        # web terminal) is running. We requested the dedicated channel precisely
        # to avoid touching the console, so don't make the fallback destructive.
        run_on_sock "$CONSOLE_SOCK" 0
    fi
elif [ -S "$CONSOLE_SOCK" ]; then
    # Console-only board (no dedicated channel was wired). Here the reset is the
    # only way to recover a fresh prompt from a possibly-stuck foreground
    # process, so keep it — there is no interactive terminal to protect.
    run_on_sock "$CONSOLE_SOCK" 1
else
    echo "No serial socket found ($CMD_SOCK or $CONSOLE_SOCK)" >&2
    exit 1
fi

if [ "$FOUND" -eq 0 ]; then
    echo "WAIRZ_SERIAL_TIMEOUT"
    exit 124
fi

printf '%s\n' "$OUTPUT"
exit "$EXIT_CODE"
