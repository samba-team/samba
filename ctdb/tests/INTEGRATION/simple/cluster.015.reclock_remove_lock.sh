#!/usr/bin/env bash

# Verify that the cluster recovers if the recovery lock is removed.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init -n

echo "Starting CTDB with cluster lock recheck interval set to 5s..."
ctdb_nodes_start_custom -r 5

generation_has_changed ()
{
	local node="$1"
	local generation_init="$2"

	# Leak this so it can be printed by test
	generation_new=""

	ctdb_onnode "$node" status
	# shellcheck disable=SC2154
	# $outfile set by ctdb_onnode() above
	generation_new=$(sed -n -e 's/^Generation:\([0-9]*\)/\1/p' "$outfile")

	[ "$generation_new" != "$generation_init" ]
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

leader_get "$test_node"

generation_get

echo "Remove recovery lock"
rm "$reclock"
echo

# This will mean an election has taken place and a recovery has occurred
wait_until_generation_has_changed "$test_node"

# shellcheck disable=SC2154
# $leader set by leader_get() above
leader_old="$leader"

leader_get "$test_node"

if [ "$leader" != "$leader_old" ] ; then
	echo "OK: Leader has changed to node ${leader_new}"
fi
echo "GOOD: Leader is still node ${leader}"
echo

cluster_is_healthy
