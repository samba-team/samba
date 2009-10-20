#!/bin/bash

test_info()
{
    cat <<EOF
Verify that the CTDB_SAMBA_SKIP_SHARE_CHECK configuration option is respected.

We create a file in /etc/ctdb/rc.local.d/ that creates a function
called testparm.  This effectively hooks the testparm command,
allowing us to provide a fake list of shares to check or not check.

We create another file in the same directory to set and unset the
CTDB_SAMBA_SKIP_SHARE_CHECK option, utilising the shell's "readonly"
built-in to ensure that our value for the option is used.

Prerequisites:

* An active CTDB cluster with at least 2 nodes with public addresses.

* Test must be run on a real or virtual cluster rather than against
  local daemons.  There is nothing intrinsic to this test that forces
  this - it is because tests run against local daemons don't use the
  regular eventscripts.

Steps:

1.  Verify that the cluster is healthy.
2.  Determine the CTDB MonitorInterval setting and remember it.
3.  Create a temporary directory using mktemp, remember the name in
    $mydir.
4.  Create an executable file /etc/ctdb/rc.local.d/fake-testparm that
    contains a definiton for the function testparm, which prints a
    share definition for a directory $mydir/foo (which does not
    currently exist).
5.  Create an executable file
    /etc/ctdb/rc.local.d/samba-skip-share-check that replaces the
    loadconfig() function by one with equivalent functionality, but
    which also sets CTDB_SAMBA_SKIP_SHARE_CHECK="no" if loading
    "ctdb" configuration.
6.  Wait for a maximum of MonitorInterval seconds for the node to
    become unhealthy.
7.  Create the directory $mydir/foo.
8.  Wait for a maximum of MonitorInterval seconds for the node to
    become healthy.
9.  Modify /etc/ctdb/rc.local.d/samba-skip-share-check so that it sets
    CTDB_SAMBA_SKIP_SHARE_CHECK="yes".
10. Remove the directory $mydir/foo.
11. Wait for MonitorInterval and confirm that the the node is still
    healthy.

Expected results:

* When an SAMBA share directory is missing CTDB should only mark a node
  as unhealthy if CTDB_SAMBA_SKIP_SHARE_CHECK is set to "no".
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
monitor_interval=$((${out#*= } + 1))

mydir=$(onnode -q $test_node mktemp -d)
rc_local_d="${CTDB_BASE:-/etc/ctdb}/rc.local.d"
mkdir -p "$rc_local_d"

my_exit_hook ()
{
    onnode -q $test_node "rm -f $mydir/*"
    onnode -q $test_node "rmdir --ignore-fail-on-non-empty $mydir"
    onnode -q $test_node "rm -f \"$rc_local_d/\"*"
    onnode -q $test_node "rmdir --ignore-fail-on-non-empty \"$rc_local_d\""
}

ctdb_test_exit_hook_add my_exit_hook

foo_dir=$mydir/foo

try_command_on_node -v $test_node "mkdir -p \"$rc_local_d\""

f="$rc_local_d/fake-testparm"
echo "Installing \"$f\"..."
# Yes, the quoting is very tricky.  We want $foo_dir and $f expanded when
# we echo the function definition but we don't want any of the other
# items expanded until the function is run.
try_command_on_node $test_node "echo 'function testparm () { tp=\$(which testparm 2>/dev/null) ; if [ -n \"\$2\" ] ; then echo path = '\"$foo_dir\"' ; else \$tp \"\$@\" ; fi ; }' >\"$f\" ; chmod +x \"$f\""

n="$rc_local_d/samba-skip-share-check"
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
        CTDB_SAMBA_SKIP_SHARE_CHECK=no
    fi
}
'
echo "Installing \"$n\" with CTDB_SAMBA_SKIP_SHARE_CHECK=no..."
try_command_on_node $test_node "echo '$n_contents' >\"$n\" ; chmod +x \"$n\""

wait_until_node_has_status $test_node unhealthy $monitor_interval

try_command_on_node -v $test_node "mkdir $foo_dir"

wait_until_node_has_status $test_node healthy $monitor_interval

echo "Re-installing \"$n\" with CTDB_SAMBA_SKIP_SHARE_CHECK=yes..."
try_command_on_node $test_node "echo '${n_contents/=no/=yes}' >\"$n\" ; chmod +x \"$n\""

try_command_on_node -v $test_node "rmdir $foo_dir"

echo "Waiting for MonitorInterval to ensure that node $test_node stays healthy..."
sleep_for $monitor_interval

wait_until_node_has_status $test_node healthy 1
