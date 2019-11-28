#!/bin/bash

test_info()
{
    cat <<EOF
Verify that TAKE_IP will work for an IP that is already on an interface

This is a variation of simple/60_recoverd_missing_ip.sh
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

select_test_node_and_ips

echo "Running test against node $test_node and IP $test_ip"

# This test puts an address on an interface and then needs to quickly
# configure that address and cause an IP takeover.  However, an IPv6
# address will be tentative for a while so "quickly" is not possible".
# When ctdb_control_takeover_ip() calls ctdb_sys_have_ip() it will
# decide that the address is not present.  It then attempts a takeip,
# which can fail if the address is suddenly present because it is no
# longer tentative.
case "$test_ip" in
*:*)
	echo "SKIPPING TEST: not supported for IPv6 addresses"
	exit 0
	;;
esac

get_test_ip_mask_and_iface

echo "Deleting IP $test_ip from all nodes"
delete_ip_from_all_nodes $test_ip
try_command_on_node -v $test_node $CTDB ipreallocate
wait_until_ips_are_on_node ! $test_node $test_ip

try_command_on_node -v all $CTDB ip

# The window here needs to small, to try to avoid the address being
# released.  The test will still pass either way but if the first IP
# takeover run does a release then this doesn't test the code path we
# expect it to...
echo "Adding IP $test_ip to $iface and CTDB on node $test_node"
ip_cmd="ip addr add $test_ip/$mask dev $iface"
ctdb_cmd="$CTDB addip $test_ip/$mask $iface && $CTDB ipreallocate"
try_command_on_node $test_node "$ip_cmd && $ctdb_cmd"

wait_until_ips_are_on_node $test_node $test_ip
