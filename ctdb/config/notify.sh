#!/bin/sh

# This is script is invoked from ctdb when certain events happen.  See
# /etc/ctdb/notify.d/README for more details.

d=$(dirname "$0")
nd="${d}/notify.d"

ok=true

for i in "${nd}/"* ; do
    # Don't run files matching basename
    case "${i##*/}" in
	*~|*,|*.rpm*|*.swp|README) continue ;;
    esac

    # Files must be executable
    [ -x "$i" ] || continue

    # Flag failures
    "$i" "$1" || ok=false
done

$ok
