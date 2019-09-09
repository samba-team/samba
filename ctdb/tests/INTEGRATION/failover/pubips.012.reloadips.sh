#!/bin/bash

test_info()
{
    cat <<EOF
Verify that IPs can be rearrranged using 'ctdb reloadips'.

Various sub-tests that remove addresses from the public_addresses file
on a node or delete the entire contents of the public_addresses file.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Expected results:

* When addresses are deconfigured "ctdb ip" no longer reports them and
  when added they are seen again.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

select_test_node_and_ips

try_command_on_node $test_node $CTDB_TEST_WRAPPER ctdb_base_show
addresses="${out}/public_addresses"
echo "Public addresses file on node $test_node is \"$addresses\""
backup="${addresses}.$$"

restore_public_addresses ()
{
    try_command_on_node $test_node "mv $backup $addresses >/dev/null 2>&1 || true"
}
ctdb_test_exit_hook_add restore_public_addresses

# ctdb reloadips will fail if it can't disable takover runs.  The most
# likely reason for this is that there is already a takeover run in
# progress.  We can't predict when this will happen, so retry if this
# occurs.
do_ctdb_reloadips ()
{
	local retry_max=10
	local retry_count=0
	while : ; do
		if try_command_on_node any "$CTDB reloadips all" ; then
			return 0
		fi

		if [ "$out" != "Failed to disable takeover runs" ] ; then
			return 1
		fi

		if [ $retry_count -ge $retry_max ] ; then
			return 1
		fi

		retry_count=$((retry_count + 1))
		echo "Retrying..."
		sleep_for 1
	done
}


echo "Removing IP $test_ip from node $test_node"

try_command_on_node $test_node "mv $addresses $backup && grep -v '^${test_ip}/' $backup >$addresses"

do_ctdb_reloadips

try_command_on_node $test_node $CTDB ip

if grep "^${test_ip} " <<<"$out" ; then
    cat <<EOF
BAD: node $test_node can still host IP $test_ip:
$out
EOF
    exit 1
fi

cat <<EOF
GOOD: node $test_node is no longer hosting IP $test_ip:
$out
EOF

try_command_on_node any $CTDB sync


echo "Restoring addresses"
restore_public_addresses

do_ctdb_reloadips

echo "Getting list of public IPs on node $test_node"
try_command_on_node $test_node "$CTDB ip | tail -n +2"

if [ -z "$out" ] ; then
    echo "BAD: node $test_node has no ips"
    exit 1
fi

cat <<EOF
GOOD: node $test_node has these addresses:
$out
EOF

try_command_on_node any $CTDB sync


echo "Emptying public addresses file on $test_node"

try_command_on_node $test_node "mv $addresses $backup && touch $addresses"

do_ctdb_reloadips

echo "Getting list of public IPs on node $test_node"
try_command_on_node $test_node "$CTDB ip | tail -n +2"

if [ -n "$out" ] ; then
    cat <<EOF
BAD: node $test_node still has ips:
$out
EOF
    exit 1
fi

echo "GOOD: no IPs left on node $test_node"
