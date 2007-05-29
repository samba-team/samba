#!/bin/sh

CTDB="./bin/ctdb"
export CTDB

$CTDB status | egrep "^vnn:" | sed -e "s/^vnn://" -e "s/ .*$//" | while read NODE; do
	xterm -geometry 30x25 -e "watch -n1 \"$CTDB -n $NODE status\"" &
done

