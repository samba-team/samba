#!/usr/bin/env bash

# Verify that if the directory containing the recovery lock is moved
# then all nodes are banned (because they can't take the lock).
# Confirm that if the directory is moved back and the bans time out
# then the cluster returns to good health.

# This simulates the cluster filesystem containing the recovery lock
# being unmounted and remounted.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init -n

echo "Starting CTDB with cluster lock recheck time set to 5s..."
ctdb_nodes_start_custom -r 5

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

# Avoid a race where the election handler can be called before the
# tunables are updated in the recovery daemon.  Ideally, since
# everything is idle, this should take one RecoverInterval
# (i.e. iteration of the monitor loop in the recovery daemon).
# However, this is the interval between loops and each loop can take
# an arbitrary amount of time.  The only way to be sure that the
# tunables have definitely been updated is to do 2 recoveries - this
# guarantees the tunables were read at the top of the loop between the
# 2 recoveries.
echo "2 recoveries to ensure that tunables have been re-read"
ctdb_onnode "$test_node" "recover"
ctdb_onnode "$test_node" "recover"

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
