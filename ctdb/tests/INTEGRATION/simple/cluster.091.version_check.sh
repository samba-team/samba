#!/bin/bash

test_info()
{
    cat <<EOF
Check that the CTDB version consistency checking operates correctly.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init

cluster_is_healthy

select_test_node

try_command_on_node -v "$test_node" ctdb version
version="$out"

major="${version%%.*}"
rest="${version#*.}"
minor="${rest%%.*}"

echo "Node ${test_node} has version ${major}.${minor}"

# Unchanged version - this should work
export CTDB_TEST_SAMBA_VERSION=$(( (major << 16) | minor ))
printf '\nRestarting node %d with CTDB_TEST_SAMBA_VERSION=0x%08x\n' \
       "$test_node" \
       "$CTDB_TEST_SAMBA_VERSION"
ctdb_nodes_restart "$test_node"
wait_until_ready
echo "GOOD: ctdbd restarted successfully on node ${test_node}"

d="$CTDB_SCRIPTS_HELPER_BINDIR"
try_command_on_node "$test_node" "${d}/ctdb-path" "pidfile" "ctdbd"
pidfile="$out"

# Changed major version - this should fail
export CTDB_TEST_SAMBA_VERSION=$(( ((major + 1) << 16) | minor ))
printf '\nRestarting node %d with CTDB_TEST_SAMBA_VERSION=0x%08x\n' \
       "$test_node" \
       "$CTDB_TEST_SAMBA_VERSION"
ctdb_nodes_restart "$test_node"
echo "Will use PID file ${pidfile} to check for ctdbd exit"
wait_until 30 ! test -f "$pidfile"
echo "GOOD: ctdbd exited early on node ${test_node}"

# Changed minor version - this should fail
export CTDB_TEST_SAMBA_VERSION=$(( (major << 16) | (minor + 1) ))
printf '\nRestarting node %d with CTDB_TEST_SAMBA_VERSION=0x%08x\n' \
       "$test_node" \
       "$CTDB_TEST_SAMBA_VERSION"
ctdb_nodes_start "$test_node"
echo "Will use PID file ${pidfile} to check for ctdbd exit"
wait_until 30 ! test -f "$pidfile"
echo "GOOD: ctdbd exited early on node ${test_node}"
