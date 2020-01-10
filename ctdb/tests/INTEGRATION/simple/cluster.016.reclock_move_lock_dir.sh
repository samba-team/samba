#!/bin/bash

# Verify that if the directory containing the recovery lock is moved
# then all nodes are banned (because they can't take the lock).
# Confirm that if the directory is moved back and the bans time out
# then the cluster returns to good health.

# This simulates the cluster filesystem containing the recovery lock
# being unmounted and remounted.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init -r 5

all_nodes_are_banned ()
{
	node="$1"

	ctdb_onnode "$node" nodestatus
	[ $? -eq 1 ]

	# shellcheck disable=SC2154
	# $out set by ctdb_onnode() above
	[ "$out" = "Warning: All nodes are banned." ]
}

select_test_node

echo "Get recovery lock setting"
# shellcheck disable=SC2154
# $test_node set by select_test_node() above
ctdb_onnode "$test_node" getreclock
# shellcheck disable=SC2154
# $out set by ctdb_onnode() above
reclock_setting="$out"

if [ -z "$reclock_setting" ] ; then
	ctdb_test_skip "Recovery lock is not set"
fi

t="${reclock_setting% 5}"
reclock="${t##* }"

if [ ! -f "$reclock" ] ; then
	ctdb_test_error "Recovery lock file \"${reclock}\" is missing"
fi

echo "Recovery lock setting is \"${reclock_setting}\""
echo "Recovery lock file is \"${reclock}\""
echo

echo "Set ban period to 30s"
ctdb_onnode all setvar RecoveryBanPeriod 30
echo

dir=$(dirname "$reclock")

echo "Rename recovery lock directory"
mv "$dir" "${dir}.$$"
echo

echo "Wait until all nodes are banned"
wait_until 60 all_nodes_are_banned "$test_node"
echo

echo "Restore recovery lock directory"
mv "${dir}.$$" "$dir"
echo

wait_until_ready 60
