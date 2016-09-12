#!/bin/bash

test_info()
{
    cat <<EOF
For external IP address management, verify that CIFS tickles are sent.

Prerequisites:

* An active CTDB cluster with at least 2 nodes with public addresses.

* Test must be run on a real or virtual cluster rather than against
  local daemons.

* Test must not be run from a cluster node.

* Clustered Samba must be listening on TCP port 445.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init "$@"

ctdb_test_check_real_cluster

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

select_test_node_and_ips

# Select a different node to move the IP address to
to_node=""
while read x to_node ; do
    if [ "$to_node" != "$test_node" ] ; then
	break
    fi
done <<<"$out"
if [ -z "$to_node" ] ; then
    die "BAD: Unable to find a target node different to ${to_node}"
fi

echo "Get mask and interface for ${test_ip}"
get_test_ip_mask_and_iface

echo "Set DisableIPFailover=1 on all nodes"
try_command_on_node all $CTDB setvar DisableIPFailover 1

echo "Give the recovery daemon some time to reload tunables"
sleep_for 5

my_exit_hook ()
{
    onnode -q all $CTDB event script enable "10.interface"
    onnode -q all $CTDB event script disable "10.external"
}
ctdb_test_exit_hook_add my_exit_hook

echo "Disable 10.interface on all nodes"
try_command_on_node all $CTDB event script disable 10.interface
echo "Enable 10.external on all nodes"
try_command_on_node all $CTDB event script enable 10.external

test_port=445

echo "Connecting to node ${test_node} on IP ${test_ip}:${test_port} with netcat..."

nc -d -w 60 $test_ip $test_port &
nc_pid=$!
ctdb_test_exit_hook_add "kill $nc_pid >/dev/null 2>&1"

wait_until_get_src_socket "tcp" "${test_ip}:${test_port}" $nc_pid "nc"
src_socket="$out"
echo "Source socket is $src_socket"

# This should happen as soon as connection is up... but unless we wait
# we sometimes beat the registration.
echo "Checking if CIFS connection is tracked by CTDB..."
wait_until 10 check_tickles $test_node $test_ip $test_port $src_socket
echo "$out"

if [ "${out/SRC: ${src_socket} /}" != "$out" ] ; then
    echo "GOOD: CIFS connection tracked OK by CTDB."
else
    echo "BAD: Socket not tracked by CTDB."
    testfailures=1
fi

tcptickle_sniff_start $src_socket "${test_ip}:${test_port}"

echo "Moving $test_ip from $test_node to $to_node"
try_command_on_node $test_node ip addr del "${test_ip}/${mask}" dev "$iface"
try_command_on_node $to_node   ip addr add "${test_ip}/${mask}" dev "$iface"
try_command_on_node $to_node   ctdb moveip "$test_ip" "$to_node"

wait_until_ips_are_on_node "$to_node" "$test_ip"

tcptickle_sniff_wait_show
