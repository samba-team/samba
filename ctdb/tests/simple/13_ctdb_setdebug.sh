#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb setdebug' works as expected.

This is a little superficial.  It checks that CTDB thinks the debug
level has been changed but doesn't actually check that logging occurs
at the new level.

A test should also be added to see if setting the debug value via a
numerical value works too.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Get the current debug level on a node, using 'ctdb getdebug'.
3. Change the debug level to some other value (e.g. EMERG) using
   'ctdb setdebug'.
4. Verify that the new debug level is correctly set using 'ctdb getdebug'.

Expected results:

* 'ctdb setdebug' correctly sets the debug level on a node.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

get_debug ()
{
    # Sets; check_debug
    local node="$1"

    local out
    
    try_command_on_node -v $node "$CTDB getdebug"
    check_debug=$(echo "$out" |
	sed -r -e 's@Node [[:digit:]]+ is at debug level ([[:alpha:]]+) \(-?[[:digit:]]+\)$@\1@')
}

set_and_check_debug ()
{
    local node="$1"
    local level="$2"

    echo "Setting debug level on node ${node} to ${level}."
    try_command_on_node $node "$CTDB setdebug ${level}"

    local check_debug
    get_debug $node

    if [ "$level" = "$check_debug" ] ; then
	echo "That seemed to work... cool!"
    else
	echo "BAD: Debug level should have changed to \"$level\" but it is \"$check_debug\"."
	testfailures=1
    fi
}

get_debug 1
initial_debug="$check_debug"

new_debug="EMERG"
[ "$initial_debug" = "$new_debug" ] && new_debug="ALERT"

set_and_check_debug 1 "$new_debug"

if [ "$testfailures" != 1 ] ; then
    echo "Returning the debug level to its initial value..."
    set_and_check_debug 1 "$initial_debug"
fi
