#!/usr/bin/env bash

# Verify that if the directory containing the cluster lock is moved
# then the current cluster leader no longer claims to be leader, and
# no other node claims to be leader.  Confirm that if the directory is
# moved back then a node will become leader.

# This simulates the cluster filesystem containing the cluster lock
# being unmounted and remounted.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init -n

echo "Starting CTDB with cluster lock recheck interval set to 5s..."
ctdb_nodes_start_custom -r 5

select_test_node

echo "Get cluster lock setting"
# shellcheck disable=SC2154
# $test_node set by select_test_node() above
ctdb_onnode "$test_node" getreclock
# shellcheck disable=SC2154
# $out set by ctdb_onnode() above
reclock_setting="$out"

if [ -z "$reclock_setting" ] ; then
	ctdb_test_skip "Cluster lock is not set"
fi

t="${reclock_setting% 5}"
reclock="${t##* }"

if [ ! -f "$reclock" ] ; then
	ctdb_test_error "Cluster lock file \"${reclock}\" is missing"
fi

echo "Cluster lock setting is \"${reclock_setting}\""
echo "Cluster lock file is \"${reclock}\""
echo

leader_get "$test_node"

dir=$(dirname "$reclock")

echo "Rename cluster lock directory"
mv "$dir" "${dir}.$$"

wait_until_leader_has_changed "$test_node"
echo

# shellcheck disable=SC2154
# $leader set by leader_get() & wait_until_leader_has_changed(), above
if [ "$leader" != "UNKNOWN" ]; then
	test_fail "BAD: leader is ${leader}"
fi

echo "OK: leader is UNKNOWN"
echo

echo 'Get "leader timeout":'
conf_tool="${CTDB_SCRIPTS_HELPER_BINDIR}/ctdb-config"
# shellcheck disable=SC2154
# $test_node set by select_test_node() above
try_command_on_node "$test_node" "${conf_tool} get cluster 'leader timeout'"
# shellcheck disable=SC2154
# $out set by ctdb_onnode() above
leader_timeout="$out"
echo "Leader timeout is ${leader_timeout}s"
echo

sleep_time=$((2 * leader_timeout))
echo "Waiting for ${sleep_time}s to confirm leader stays UNKNOWN"
sleep_for $sleep_time

leader_get "$test_node"
if [ "$leader" = "UNKNOWN" ]; then
	echo "OK: leader is UNKNOWN"
	echo
else
	test_fail "BAD: leader is ${leader}"
fi

echo "Restore cluster lock directory"
mv "${dir}.$$" "$dir"

wait_until_leader_has_changed "$test_node"
