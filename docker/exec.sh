#!/bin/sh
# Run one sta command inside the container.
# The container runs as root (USB access), so give the files back to the host user.
PYTHONPATH="$STA_DIR/src" python -m sta "$@"
rc=$?
if [ -n "${HOST_UID:-}" ]; then
  chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$STA_DIR/cases" "$STA_DIR/kb/cache" 2>/dev/null
fi
exit $rc
