#!/bin/sh
# onnode script for rsh

if [ $# -lt 2 ]; then
cat <<EOF
Usage: onnode <nodenum|all> <command>
EOF
exit 1
fi

NODE="$1"
shift
SCRIPT="$*"

NODES=/etc/ctdb/nodes

NUMNODES=`egrep '^[[:alnum:]]' $NODES | wc -l`
MAXNODE=`expr $NUMNODES - 1`

if [ $NODE = "all" ]; then
    for a in `egrep '^[[:alnum:]]' $NODES`; do
	if [ -f "$SCRIPT" ]; then
	    rsh $a at -f $SCRIPT now
	else
	    rsh $a $SCRIPT
	fi
    done
    exit 0
fi

if [ $NODE -gt $MAXNODE ]; then
    echo "Node $NODE doesn't exist"
    exit 1
fi

NODEPLUSONE=`expr $NODE + 1`
a=`egrep '^[[:alnum:]]' $NODES | head -$NODEPLUSONE | tail -1`

if [ -f "$SCRIPT" ]; then
    exec rsh $a at -f $SCRIPT now
else
    exec rsh $a $SCRIPT
fi
