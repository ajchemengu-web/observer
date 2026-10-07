#!/usr/bin/env bash
# Launches The Observer in its own terminal window when a desktop terminal
# emulator is available; otherwise just runs it in the current terminal.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

CMD="cd '$(pwd)' && python3 -m observer; exec \$SHELL"

if [[ "${OSTYPE:-}" == darwin* ]]; then
    osascript -e "tell application \"Terminal\" to do script \"$CMD\""
    exit 0
fi

for term in gnome-terminal konsole xfce4-terminal x-terminal-emulator alacritty kitty xterm; do
    if command -v "$term" >/dev/null 2>&1; then
        case "$term" in
            gnome-terminal) gnome-terminal -- bash -c "$CMD" & ;;
            konsole)        konsole -e bash -c "$CMD" & ;;
            xfce4-terminal) xfce4-terminal -e "bash -c \"$CMD\"" & ;;
            alacritty)      alacritty -e bash -c "$CMD" & ;;
            kitty)          kitty bash -c "$CMD" & ;;
            *)              "$term" -e bash -c "$CMD" & ;;
        esac
        exit 0
    fi
done

echo "No desktop terminal emulator found — running The Observer here instead."
exec python3 -m observer
