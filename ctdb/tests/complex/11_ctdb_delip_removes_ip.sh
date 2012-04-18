#!/bin/bash

test_info()
{
    cat <<EOF
Verify that a node's public IP address can be deleted using 'ctdb deleteip'.

Check that the address is actually deleted from the interface.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

* Test must be run on a real or virtual cluster rather than against
  local daemons.  There is nothing intrinsic to this test that forces
  this - it is because tests run against local daemons don't use the
  regular eventscripts.  Local daemons put public addresses on
  loopback, so we can't reliably test when IPs have moved between
  nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Use 'ctdb ip' on one of the nodes to list the IP addresses being
   served.
3. Select an IP address being served by the node and check that it
   actually appears on the interface it is supposed to be on.
4. Delete the IP address using 'ctdb delip'.
5. Verify that the deleted IP address is no longer listed using the
   all_ips_on_node helper function.
6. Verify that the deleted IP address no longer appears on the
   interface it was on.

Expected results:

* 'ctdb delip' removes an IP address from the list of public IP
  addresses being served by a node and from the network interface.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init "$@"

ctdb_test_check_real_cluster

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

echo "Getting list of public IPs..."
all_ips_on_node -v 0

# Select an IP/node to remove.
num_ips=$(echo "$out" | wc -l)
num_to_remove=$(($RANDOM % $num_ips))

# Find the details in the list.
i=0
while [ $i -le $num_to_remove ] ; do
    read ip_to_remove test_node
    i=$(($i + 1))
done <<<"$out"

echo "Determining interface for ${ip_to_remove} on ${test_node}."
try_command_on_node $test_node "ctdb ip -Y -v"
iface=$(echo "$out" | awk -F: -v ip=${ip_to_remove} -v pnn=${test_node} '$2 == ip && $3 == pnn { print $4 }')
echo "$iface"
[ -n "$iface" ]

echo "Checking that node ${test_node} hosts ${ip_to_remove} on interface ${iface}..."
try_command_on_node $test_node "ip addr show dev $iface | grep -E 'inet[[:space:]]*${ip_to_remove}/'"

echo "Attempting to remove ${ip_to_remove} from node ${test_node}."
try_command_on_node $test_node $CTDB delip $ip_to_remove

echo "Sleeping..."
sleep_for 1

test_node_ips=""
while read ip pnn ; do
    [ "$pnn" = "$test_node" ] && \
	test_node_ips="${test_node_ips}${test_node_ips:+ }${ip}"
done <<<"$out" # bashism to avoid problem setting variable in pipeline.

if [ "${test_node_ips/${ip_to_remove}}" = "$test_node_ips" ] ; then
    echo "GOOD: That worked!"
else
    echo "BAD: The remove IP address is still there!"
    testfailures=1
fi

timeout=60
increment=5
count=0
echo "Waiting for ${ip_to_remove} to disappear from ${iface}..."
while : ; do
    try_command_on_node -v $test_node "ip addr show dev $iface"
    if echo "$out" | grep -E 'inet[[:space:]]*${ip_to_remove}/'; then
	echo "Still there..."
	if [ $(($count * $increment)) -ge $timeout ] ; then
	    echo "BAD: Timed out waiting..."
	    exit 1
	fi
	sleep_for $increment
	count=$(($count + 1))
    else
	break
    fi
done

echo "GOOD: IP was successfully removed!"
