#!/bin/bash

test_info()
{
    cat <<EOF
Verify that the reconvery daemon handles unhosted IPs properly.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

select_test_node_and_ips

echo "Running test against node $test_node and IP $test_ip"

# Find the interface
try_command_on_node $test_node "$CTDB ip -v -Y | awk -F: -v ip=$test_ip '\$2 == ip { print \$4 }'"
iface="$out"

if [ -z "$TEST_LOCAL_DAEMONS" ] ; then
    # Find the netmask
    try_command_on_node $test_node ip addr show to $test_ip
    mask="${out##*/}"
    mask="${mask%% *}"
else
    mask="24"
fi

echo "$test_ip/$mask is on $iface"

echo "Deleting IP $test_ip from all nodes"
try_command_on_node -v $test_node $CTDB delip -n all $test_ip

wait_until_ips_are_on_nodeglob '!' $test_node $test_ip

try_command_on_node -v all $CTDB ip

my_exit_hook ()
{
    if [ -z "$TEST_LOCAL_DAEMONS" ] ; then
	onnode -q all $CTDB enablescript "10.interface"
    fi
}

ctdb_test_exit_hook_add my_exit_hook

if [ -z "$TEST_LOCAL_DAEMONS" ] ; then
    # Stop monitor events from bringing up the link status of an interface
    try_command_on_node $test_node $CTDB disablescript 10.interface
fi

# This effectively cancels any monitor event that is in progress and
# runs a new one
try_command_on_node $test_node $CTDB eventscript monitor

echo "Marking interface $iface down on node $test_node"
try_command_on_node $test_node $CTDB setifacelink $iface down

try_command_on_node $test_node $CTDB clearlog recoverd

echo "Adding IP $test_ip to node $test_node"
try_command_on_node $test_node $CTDB addip $test_ip/$mask $iface

# Give the recovery daemon enough time to start doing IP verification
sleep_for 15

try_command_on_node $test_node $CTDB getlog recoverd

msg="Public IP '$test_ip' is not assigned and we could serve it"

echo "$msg"

if grep "$msg"  <<<"$out" ; then
    echo "BAD: the recovery daemon noticed that the IP was unhosted"
    exit 1
else
    echo "GOOD: the recovery daemon did not notice that the IP was unhosted"
fi

try_command_on_node $test_node $CTDB clearlog recoverd

echo "Marking interface $iface up on node $test_node"
try_command_on_node $test_node $CTDB setifacelink $iface up

wait_until_ips_are_on_nodeglob $test_node $test_ip

try_command_on_node -v $test_node $CTDB getlog recoverd

if grep "$msg" <<<"$out" ; then
    echo "GOOD: the recovery daemon noticed that the IP was unhosted"
else
    echo "BAD: the recovery daemon did not notice that the IP was unhosted"
    exit 1
fi
