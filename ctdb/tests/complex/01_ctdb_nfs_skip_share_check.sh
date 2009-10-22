#!/bin/bash

test_info()
{
    cat <<EOF
Verify that the CTDB_NFS_SKIP_SHARE_CHECK configuration option is respected.

We create a file in /etc/ctdb/rc.local.d/ that creates a function
called exportfs.  This effectively hooks the exportfs command,
allowing us to provide a fake list of shares to check or not check.

We create another file in the same directory to set and unset the
CTDB_NFS_SKIP_SHARE_CHECK option, utilising the shell's "readonly"
built-in to ensure that our value for the option is used.

Prerequisites:

* An active CTDB cluster with at least 2 nodes with public addresses.

* Test must be run on a real or virtual cluster rather than against
  local daemons.  There is nothing intrinsic to this test that forces
  this - it is because tests run against local daemons don't use the
  regular eventscripts.

Steps:

1.  Verify that the cluster is healthy.
2.  Determine a timeout for state changes by adding MonitorInterval
    and EventScriptTimeout.
3.  Create a temporary directory on the test node using mktemp,
    remember the name in $mydir.
4.  On the test node create an executable file
    /etc/ctdb/rc.local.d/fake-exportfs that contains a definiton for
    the function exportfs, which prints a share definition for a
    directory $mydir/foo (which does not currently exist).
5.  On the test node create an executable file
    /etc/ctdb/rc.local.d/nfs-skip-share-check that replaces the
    loadconfig() function by one with equivalent functionality, but
    which also sets CTDB_NFS_SKIP_SHARE_CHECK="no" if loading
    "ctdb" configuration.
6.  Wait for the test node to become unhealthy.
7.  Create the directory $mydir/foo.
8.  Wait for the test node to become healthy.
9.  Modify /etc/ctdb/rc.local.d/nfs-skip-share-check so that it sets
    CTDB_NFS_SKIP_SHARE_CHECK to "yes".
10. Remove the directory $mydir/foo.
11. Wait for  a monitor event and confirm that the the node is still
    healthy.

Expected results:

* When an NFS share directory is missing CTDB should only mark a node
  as unhealthy if CTDB_NFS_SKIP_SHARE_CHECK is set to "no".
EOF
}

. ctdb_test_functions.bash

set -e

ctdb_test_init "$@"

ctdb_test_check_real_cluster

cluster_is_healthy

select_test_node_and_ips

# We need this for later, so we know how long to sleep.
try_command_on_node $test_node $CTDB getvar MonitorInterval
monitor_interval=${out#*= }
try_command_on_node $test_node $CTDB getvar EventScriptTimeout
event_script_timeout=${out#*= }

monitor_timeout=$(($monitor_interval + $event_script_timeout))

echo "Using timeout of ${monitor_timeout}s (MonitorInterval + EventScriptTimeout)..."


mydir=$(onnode -q $test_node mktemp -d)
rc_local_d="${CTDB_BASE:-/etc/ctdb}/rc.local.d"

my_exit_hook ()
{
    ctdb_test_eventscript_uninstall
    onnode -q $test_node "rm -f $mydir/*"
    onnode -q $test_node "rmdir --ignore-fail-on-non-empty $mydir"
    onnode -q $test_node "rm -f \"$rc_local_d/\"*"
    onnode -q $test_node "rmdir --ignore-fail-on-non-empty \"$rc_local_d\""
}

ctdb_test_exit_hook_add my_exit_hook

ctdb_test_eventscript_install

foo_dir=$mydir/foo

try_command_on_node -v $test_node "mkdir -p \"$rc_local_d\""

f="$rc_local_d/fake-exportfs"
echo "Installing \"$f\"..."
try_command_on_node $test_node "echo \"function exportfs () { echo $foo_dir 127.0.0.1/32 ; }\" >\"$f\" ; chmod +x \"$f\""

n="$rc_local_d/nfs-skip-share-check"
n_contents='loadconfig() {
    name="$1"
    if [ -f /etc/sysconfig/$name ]; then
	. /etc/sysconfig/$name
    elif [ -f /etc/default/$name ]; then
	. /etc/default/$name
    elif [ -f $CTDB_BASE/sysconfig/$name ]; then
	. $CTDB_BASE/sysconfig/$name
    fi
    if [ "$name" = "ctdb" ] ; then
        CTDB_NFS_SKIP_SHARE_CHECK=no
    fi
}
'
echo "Installing \"$n\" with CTDB_NSF_SKIP_SHARE_CHECK=no..."
try_command_on_node $test_node "echo '$n_contents' >\"$n\" ; chmod +x \"$n\""

wait_until_node_has_status $test_node unhealthy $monitor_timeout

try_command_on_node -v $test_node "mkdir $foo_dir"

wait_until_node_has_status $test_node healthy $monitor_timeout

echo "Re-installing \"$n\" with CTDB_NFS_SKIP_SHARE_CHECK=yes..."
try_command_on_node $test_node "echo '${n_contents/=no/=yes}' >\"$n\" ; chmod +x \"$n\""

try_command_on_node -v $test_node "rmdir $foo_dir"

wait_for_monitor_event $test_node

wait_until_node_has_status $test_node healthy 1
