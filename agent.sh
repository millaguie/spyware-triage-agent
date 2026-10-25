#!/usr/bin/env bash
# Old name of ./start, kept so existing notes still work.
exec "$(dirname "$(readlink -f "$0")")/start" "$@"
