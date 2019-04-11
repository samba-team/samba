#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb listnodes' shows the list of nodes in a ctdb cluster.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run 'ctdb listnodes' on all the nodes of the cluster.
3. Verify that one all the nodes the command displays a list of
   current cluster nodes.

Expected results:

* 'ctdb listnodes' displays the correct information.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

try_command_on_node -v 0 "$CTDB listnodes"

num_nodes=$(wc -l <"$outfile")

# Each line should look like an IP address.
ipv4_pat='[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+'
ipv6_pat='[[:xdigit:]]+:[[:xdigit:]:]+[[:xdigit:]]+'
sanity_check_output \
    2 \
    "^${ipv4_pat}|${ipv6_pat}\$"

out_0="$out"

echo "Checking other nodes..."

n=1
while [ $n -lt $num_nodes ] ; do
    echo -n "Node ${n}: "
    try_command_on_node $n "$CTDB listnodes"
    if [ "$out_0" = "$out" ] ; then
	echo "OK"
    else
	echo "DIFFERs from node 0:"
	echo "$out"
	exit 1
    fi
    n=$(($n + 1))
done
