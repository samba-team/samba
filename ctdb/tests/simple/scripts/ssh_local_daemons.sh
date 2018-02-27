#!/bin/sh

nodes="${CTDB_NODES:-${CTDB_BASE}/nodes}"

# ssh options can't be used so discard them
while : ; do
	case "$1" in
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

# Determine the correct Unix domain socket
export CTDB_SOCKET=""
n=0
for s in $CTDB_NODES_SOCKETS ; do
	if [ $n -eq $pnn ] ; then
		CTDB_SOCKET="$s"
		break
	fi
	n=$((n + 1))
done
if [ -z "$CTDB_SOCKET" ] ; then
	echo "$0: Unable to find socket for node ${ip}" >&2
	exit 1
fi

# Now
exec sh -c "$command"
