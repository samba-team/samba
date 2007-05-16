#!/bin/sh

CTDB_CONTROL="./bin/ctdb_control"
export CTDB_CONTROL

$CTDB_CONTROL getnodemap 0 | egrep "^vnn:" | sed -e "s/^vnn://" -e "s/ .*$//" | while read NODE; do
	xterm -geometry 30x25 -e "watch -n1 \"$CTDB_CONTROL getnodemap $NODE; $CTDB_CONTROL getvnnmap $NODE; $CTDB_CONTROL getrecmode $NODE; $CTDB_CONTROL getrecmaster $NODE\"" &

done



