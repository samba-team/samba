#!/bin/bash

test_info()
{
    cat <<EOF
Verify that it is possible to SSH to a public address after disabling a node.

We SSH to a public IP and check the hostname, disable the node hosting
it and then SSH again to confirm that the hostname has changed.

Prerequisites:

* An active CTDB cluster with at least 2 nodes with public addresses.

* Test must be run on a real or virtual cluster rather than against
  local daemons.

* Test must not be run from a cluster node.

Steps:

1. Verify that the cluster is healthy.
2. Select a public address and its corresponding node.
3. SSH to the selected public address and run hostname.
4. Disable the selected node.
5. SSH to the selected public address again and run hostname.

Expected results:

* When a node is disabled the public address fails over and it is
  still possible to SSH to the node.  The hostname should change.
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

echo "Removing ${test_ip} from the local neighbor table..."
ip neigh flush "$test_prefix" >/dev/null 2>&1 || true

echo "SSHing to ${test_ip} and running hostname..."
if ! original_hostname=$(ssh -o "StrictHostKeyChecking no" $test_ip hostname) ; then
    die "Failed to get original hostname via SSH..."
fi

echo "Hostname is: ${original_hostname}"

gratarp_sniff_start

echo "Disabling node $test_node"
try_command_on_node 1 $CTDB disable -n $test_node
wait_until_node_has_status $test_node disabled

gratarp_sniff_wait_show

echo "SSHing to ${test_ip} and running hostname (again)..."
if ! new_hostname=$(ssh -o "StrictHostKeyChecking no" $test_ip hostname) ; then
    echo "Failed to get new hostname via SSH..."
    echo "DEBUG:"
    ip neigh show
    exit 1
fi

echo "Hostname is: ${new_hostname}"

if [ "$original_hostname" != "$new_hostname" ] ; then
    echo "GOOD: hostname changed"
else
    echo "BAD: hostname did not change"
    testfailures=1
fi
