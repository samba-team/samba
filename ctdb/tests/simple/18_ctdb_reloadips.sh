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

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

select_test_node_and_ips

echo "Emptying public addresses file on $test_node"

addresses=$(get_ctdbd_command_line_option $test_node "public-addresses")
echo "Public addresses file on node $test_node is \"$addresses\""
backup="${addresses}.$$"

restore_public_addresses ()
{
    try_command_on_node $test_node "mv $backup $addresses >/dev/null 2>&1 || true"
}
ctdb_test_exit_hook_add restore_public_addresses

try_command_on_node $test_node "mv $addresses $backup && touch $addresses"

try_command_on_node any $CTDB reloadips all

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

echo "Restoring addresses"
restore_public_addresses

try_command_on_node any $CTDB reloadips all

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

select_test_node_and_ips

echo "Removing IP $test_ip from node $test_node"

try_command_on_node $test_node "mv $addresses $backup && grep -v '^${test_ip}/' $backup >$addresses"

try_command_on_node any $CTDB reloadips all

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
