#!/bin/sh
# Launcher: picks python3 or python (Windows/Git Bash and macOS often have only one). Passes stdin through.
here="$(cd "$(dirname "$0")" && pwd)"
if command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
  exec python3 "$here/$1"
elif command -v python >/dev/null 2>&1; then
  exec python "$here/$1"
fi
exit 0  # no Python: fail open, the hook is a safety net, not a gate
