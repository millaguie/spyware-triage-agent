#!/bin/sh
# Start the daemons once, so they live as long as the container:
#   usbmuxd for iPhones; the adb server, so a phone authorized once stays
#   authorized for every ./sta command (a server started inside one
#   `docker compose exec` dies when that command ends).
usbmuxd --foreground --user root >/var/log/usbmuxd.log 2>&1 &
adb start-server >/var/log/adb.log 2>&1 &  # can block until a phone is authorized
exec "$@"
