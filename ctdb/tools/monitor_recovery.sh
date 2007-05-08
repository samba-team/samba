#!/bin/sh

CTDB_CONTROL=./bin/ctdb_control
XPOS=0

$CTDB_CONTROL getnodemap 0 | egrep "^vnn:" | sed -e "s/^vnn://" -e "s/ .*$//" | while read NODE; do
	xterm -geometry 30x25+$XPOS -e "while true; do sleep 1; clear; $CTDB_CONTROL getnodemap $NODE; $CTDB_CONTROL getvnnmap $NODE; $CTDB_CONTROL getrecmode $NODE; $CTDB_CONTROL getrecmaster $NODE;done" &
	export XPOS=`expr $XPOS "+" "200"`

done



