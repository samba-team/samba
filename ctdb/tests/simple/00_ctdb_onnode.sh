#!/bin/bash

test_info()
{
    cat <<EOF
Use 'onnode' to confirm connectivity between all cluster nodes.

Steps:

1. Do a recursive "onnode all" to make sure all the nodes can connect
   to each other.  On a cluster this ensures that SSH keys are known
   between all hosts, which will stop output being corrupted with
   messages about nodes being added to the list of known hosts.

Expected results:

* 'onnode' works between all nodes.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"


# 

echo "Checking connectivity between nodes..."
onnode all onnode -p all hostname

# We're seeing some weirdness with CTDB controls timing out.  We're
# wondering if time is jumping forward, so this creates a time log on
# each node that we can examine later if tests fail weirdly.
if [ -z "$TEST_LOCAL_DAEMONS" -a -n "$CTDB_TEST_TIME_LOGGING" ] ; then
    echo "Starting time logging on each node..."
    f="${TEST_VAR_DIR}/ctdb.test.time.log"
    onnode -p all "[ -f $f ] || while : ; do date '+%s %N' ; sleep 1 ; done >$f 2>&1 </dev/null &"  &
fi
