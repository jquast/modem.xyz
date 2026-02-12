#!/bin/bash
# Helper script running inside a terminal instance (kitty or wezterm).
# Reads banner payloads from a named pipe, clears screen, displays each one,
# then signals readiness for screenshot via a second named pipe.
#
# Args: DATA_FIFO READY_FIFO WINDOW_TITLE

DATA_PIPE="$1"
READY_PIPE="$2"
WINDOW_TITLE="$3"

# Disable echo so terminal report responses don't appear on screen
stty -echo

# Set terminal title for xdotool window discovery
printf '\033]0;%s\007' "$WINDOW_TITLE"

while true; do
    # Block until controller sends a banner (or empty = shutdown)
    payload=$(cat "$DATA_PIPE")
    [ -z "$payload" ] && break

    # Reset terminal, hide cursor
    printf '\033c\033[?25l'

    # Restore window title (reset clears it)
    printf '\033]0;%s\007' "$WINDOW_TITLE"

    # Re-disable echo (reset re-enables it)
    stty -echo

    # Display the banner, hide cursor again just in case
    printf '%s\033[?25l' "$payload"

    # Drain any terminal report responses from stdin
    # and pause to ensure display is complete for screenshot,
    while read -t 0.05 -r -n 256 _discard 2>/dev/null; do :; done

    # Signal controller: "ready for screenshot"
    echo "ready" > "$READY_PIPE"
done
