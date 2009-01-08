#!/bin/bash

test_info()
{
    cat <<EOF
Verify an error occurs if a ctdb command is run against a node without a ctdbd.

That is, check that an error message is printed if an attempt is made
to execute a ctdb command against a node that is not running ctdbd.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Shutdown ctdb on a node using 'ctdb shutdown -n <node>'.
3. Verify that the status of the node changes to 'DISCONNECTED'.
4. Now run 'ctdb ip -n <node>' from another node.
5. Verify that an error message is printed stating that the node is
   disconnected.
6. Execute some other commands against the shutdown node.  For example,
   disable, enable, ban, unban, listvars.
7. For each command, verify that an error message is printed stating
   that the node is disconnected. 

Expected results:

* For a node on which ctdb is not running, all commands display an
  error message stating that the node is disconnected.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

test_node=1

try_command_on_node 0 "$CTDB listnodes"
num_nodes=$(echo "$out" | wc -l)
echo "There are $num_nodes nodes."

echo "Shutting down node ${test_node}..."
try_command_on_node $test_node $CTDB shutdown

onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status $test_node disconnected

pat="ctdb_control error: 'ctdb_control to disconnected node'|Node $test_node is DISCONNECTED"

for i in ip disable enable "ban 0" unban listvars ; do
    try_command_on_node -v 0 ! $CTDB $i -n $test_node

    if egrep -q "$pat" <<<"$out" ; then
	echo "OK: \"ctdb ${i}\" fails with \"disconnected node\""
    else
	echo "BAD: \"ctdb ${i}\" does not fail with \"disconnected node\""
	exit 1
    fi
done

echo "That all looks OK.  Restarting cluster..."

restart_ctdb

ctdb_test_exit
