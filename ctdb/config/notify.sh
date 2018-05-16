#!/bin/sh

# This is script is invoked from ctdb when certain events happen.  See
# /etc/ctdb/events/notification/README for more details.

d=$(dirname "$0")
nd="${d}/events/notification"

ok=true

for i in "${nd}/"*.script ; do
    # Files must be executable
    [ -x "$i" ] || continue

    # Flag failures
    "$i" "$1" || ok=false
done

$ok
