#!/bin/sh

nodes="${CTDB_BASE}/nodes"

# Only try to respect ssh -n option, others can't be used so discard them
close_stdin=false
while : ; do
	case "$1" in
	-n) close_stdin=true ; shift ;;
	-*) shift ;;
	*) break ;;
	esac
done

if [ $# -ne 2 ] ; then
	echo "usage: $0 <ip> <command>" >&2
	exit 1
fi

# IP adress of node. onnode can pass hostnames but not in these tests
ip="$1"
# Complete command is provide by onnode as a single argument
command="$2"

num=$(awk -v ip="$ip" '$1 == ip { print NR }' "$nodes")
pnn=$((num - 1))

# Determine the correct CTDB base directory
export CTDB_BASE=""
n=0
for b in $CTDB_BASES ; do
	if [ $n -eq $pnn ] ; then
		CTDB_BASE="$b"
		break
	fi
	n=$((n + 1))
done

if [ -z "$CTDB_BASE" ] ; then
	echo "$0: Unable to find base for node ${ip}" >&2
	exit 1
fi

if $close_stdin ; then
	exec sh -c "$command" <&-
else
	exec sh -c "$command"
fi
