#!/bin/bash

test_info()
{
    cat <<EOF
Verify that a file created on a node is readable via NFS after a failover.

We write a file into an exported directory on a node, mount the NFS
share from a node, verify that we can read the file via NFS and that
we can still read it after a failover.

Prerequisites:

* An active CTDB cluster with at least 2 nodes with public addresses.

* Test must be run on a real or virtual cluster rather than against
  local daemons.

* Test must not be run from a cluster node.

Steps:

1.  Verify that the cluster is healthy.
2.  Select a public address and its corresponding node.
3.  Select the 1st NFS share exported on the node.
4.  Write a file into exported directory on the node and calculate its
    checksum.
5.  Mount the selected NFS share.
6.  Read the file via the NFS mount and calculate its checksum.
7.  Compare checksums.
8.  Disable the selected node.
9.  Read the file via NFS and calculate its checksum.
10. Compare the checksums.

Expected results:

* Checksums for the file on all 3 occasions should be the same.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init "$@"

ctdb_test_check_real_cluster

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

nfs_test_setup

echo "Create file containing random data..."
local_f=$(mktemp)
ctdb_test_exit_hook_add rm -f "$local_f"
dd if=/dev/urandom of=$local_f bs=1k count=1
local_sum=$(sum $local_f)

scp -p "$local_f" "[${test_ip}]:${nfs_remote_file}"
try_command_on_node $test_node "chmod 644 $nfs_remote_file"

nfs_sum=$(sum $nfs_local_file)

if [ "$local_sum" = "$nfs_sum" ] ; then
    echo "GOOD: file contents read correctly via NFS"
else
    echo "BAD: file contents are different over NFS"
    echo "  original file: $local_sum"
    echo "       NFS file: $nfs_sum"
    exit 1
fi

gratarp_sniff_start

echo "Disabling node $test_node"
try_command_on_node 0 $CTDB disable -n $test_node
wait_until_node_has_status $test_node disabled

gratarp_sniff_wait_show

new_sum=$(sum $nfs_local_file)
[ $? -eq 0 ]

if [ "$nfs_sum" = "$new_sum" ] ; then
    echo "GOOD: file contents unchanged after failover"
else
    echo "BAD: file contents are different after failover"
    echo "  original file: $nfs_sum"
    echo "       NFS file: $new_sum"
    exit 1
fi
