#!/bin/bash

test_info()
{
    cat <<EOF
Verify 'ctdb getmonmode' works correctly.

This test doesn't actually verify that enabling and disabling
monitoring mode actually does that.  It trusts ctdb that the
monitoring mode is modified as requested.  21_ctdb_disablemonitor.sh
does some more useful checking.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Use 'ctdb getmodmode -n <node>' to get the current monitoring mode.
3. Verify that it shows monitoring as 'active'.
4. Verify that the command prints the output in colon-separated format
   when run with the '-Y' option.
5. Disable monitoring on the node using 'ctdb disablemonitor'.
6. Verify that it shows monitoring as 'disabled'.

Expected results:

* 'ctdb getmonmode' works as expected.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

test_node=1

try_command_on_node -v 0 $CTDB getmonmode -n $test_node

sanity_check_output \
    1 \
    '^Monitoring mode:ACTIVE \(0\)$' \
    "$out"

colons=$(printf ':mode:\n:0:')

try_command_on_node -v 0 $CTDB -Y getmonmode -n $test_node

if [ "$out" = "$colons" ] ; then
    echo "Looks OK"
else
    echo "BAD: -Y output isn't what was expected"
    testfailures=1
fi

try_command_on_node -v 0 $CTDB disablemonitor -n $test_node

onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status $test_node monoff

echo "That worked!  Restarting cluster to restore configuration..."

restart_ctdb

ctdb_test_exit
