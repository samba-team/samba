#!/bin/bash

# Verify that the nodes file can be effectively reloaded

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init

echo "Get list of nodes"
ctdb_get_all_pnns

# $all_pnns is set above by ctdb_get_all_pnns()
# shellcheck disable=SC2154
original_nodes_onnode="$all_pnns"
first=$(echo "$all_pnns" | sed -n -e '1p')
second=$(echo "$all_pnns" | sed -n -e '2p')
not_second=$(echo "$all_pnns" | grep -Fvx "$second")

echo

echo "Run \"ctdb nodestatus all\" on node ${first}"
ctdb_onnode "$first" "nodestatus all"

echo "Extract list of nodes from \"ctdb nodestatus all\" output"
# $outfile is set above by ctdb_onnode()
# shellcheck disable=SC2154
original_nodes_nodestatus=$(sed -n 's|^pnn:\([0-9][0-9]*\) .*|\1|p' "$outfile")

if [ "$original_nodes_onnode" != "$original_nodes_nodestatus" ]; then
	ctdb_test_fail "BAD: onnode does not agree with ctdb nodestatus"
fi

echo "GOOD: PNN list agrees with ctdb nodestatus"

echo

echo "Mark node ${second} as deleted in nodes files"

get_nodes_file()
{
	local node="$1"

	function_onnode "$node" "ctdb_base_show"
	# $out is set above by function_onnode()
	# shellcheck disable=SC2154
	echo "${out}/nodes"
}

for i in $original_nodes_onnode; do
	nodes_file=$(get_nodes_file "$i")
	linenum=$((second + 1))
	try_command_on_node "$i" "sed -i -e '${linenum}s|^|#|' '$nodes_file'"
done

echo

status=0
echo "Run \"ctdb reloadnodes\" on node ${first} - THIS WILL FAIL"
ctdb_onnode "$first" "reloadnodes" || status=$?
if [ $status -ne 1 ]; then
	ctdb_test_fail "ERROR: reloadnodes worked with connected deleted node"
fi

echo

echo "Shut down node ${second}"
ctdb_onnode "$second" "shutdown"

wait_until_node_has_status "$second" "disconnected" 30 "$first"

echo

echo "Wait for recoveries to complete"
wait_until 30 ctdb_onnode "$first" "recover"

echo "Run \"ctdb reloadnodes\" on node ${first}"
ctdb_onnode "$first" "reloadnodes"

echo

# All connected nodes should have reloaded
for n in $not_second; do
	echo "Run \"ctdb nodestatus all\" on node ${n}"
	ctdb_onnode "$n" "nodestatus all"

	echo "Extract list of nodes from \"ctdb nodestatus all\" output"
	nodes_nodestatus=$(sed -n 's|^pnn:\([0-9][0-9]*\) .*|\1|p' "$outfile")

	if [ "$not_second" != "$nodes_nodestatus" ]; then
		echo "BAD: new nodes list not as expected on node ${n}"
		echo "Expected: ${not_second}"
		echo "Found: ${nodes_nodestatus}"
		ctdb_test_fail
	fi

	echo "GOOD: new nodes list as expected on node ${n}"
done

echo

echo "Undelete node ${second} in nodes files"

for i in $original_nodes_onnode; do
	nodes_file=$(get_nodes_file "$i")
	linenum=$((second + 1))
	try_command_on_node "$i" "sed -i -e '${linenum}s|^#||' '$nodes_file'"
done

echo

echo "Wait for recoveries to complete"
wait_until 30 ctdb_onnode "$first" "recover"

echo
echo "Run \"ctdb reloadnodes\" on node ${first}"
ctdb_onnode "$first" "reloadnodes"

echo

# All connected nodes should have reloaded
for n in $not_second; do
	echo "Run \"ctdb nodestatus all\" on node ${n}"
	status=0
	ctdb_onnode "$n" "nodestatus all" || status=$?

	# DISCONNECTED + UNHEALTHY = 3
	if [ $status -ne 3 ]; then
		printf 'BAD: nodestatus returned %d on node %s, expected 3\n' \
			$status "$n"
		ctdb_test_fail
	fi

	echo "GOOD: nodestatus returned ${status} on node ${n}"

	echo "Extract list of nodes from \"ctdb nodestatus all\" output"
	nodes_nodestatus=$(sed -n 's|^pnn:\([0-9][0-9]*\) .*|\1|p' "$outfile")

	if [ "$original_nodes_nodestatus" != "$nodes_nodestatus" ]; then
		echo "BAD: new nodes list not as expected on node ${n}"
		echo "Expected: ${original_nodes_nodestatus}"
		echo "Found: ${nodes_nodestatus}"
		ctdb_test_fail
	fi

	echo "GOOD: new nodes list as expected on node ${n}"
done

echo

echo "Restart node ${second}"
ctdb_nodes_start "$second"

wait_until_node_has_status "$second" "connected" 30 "$first"

wait_until_ready

echo

echo "Check \"ctdb nodestatus all\" on node ${first}"
ctdb_onnode "$first" "nodestatus all"

echo "Check \"ctdb nodestatus all\" on node ${second}"
ctdb_onnode "$second" "nodestatus all"
