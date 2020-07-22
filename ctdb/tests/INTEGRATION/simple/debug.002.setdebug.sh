#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb setdebug' works as expected.

This is a little superficial.  It checks that CTDB thinks the debug
level has been changed but doesn't actually check that logging occurs
at the new level.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

select_test_node

get_debug ()
{
    # Sets: check_debug
    local node="$1"

    local out

    try_command_on_node -v $node "$CTDB getdebug"
    check_debug="$out"
}

set_and_check_debug ()
{
    local node="$1"
    local level="$2"
    local levelstr="${3:-$level}"

    echo "Setting debug level on node ${node} to ${level}."
    try_command_on_node $node "$CTDB setdebug ${level}"

    local check_debug
    get_debug $node

    if [ "$levelstr" != "$check_debug" ] ; then
	die "BAD: Debug level \"$levelstr\" != \"$check_debug\"."
    fi
}

get_debug $test_node
initial_debug="$check_debug"

levels="ERROR WARNING NOTICE INFO DEBUG"

for new_debug in $levels ; do
    [ "$initial_debug" != "$new_debug" ] || continue

    echo
    set_and_check_debug $test_node "$new_debug"
done

while read new_debug i ; do
    [ "$initial_debug" != "$i" ] || continue

    echo
    set_and_check_debug $test_node "$i" "$new_debug"
done <<EOF
ERROR 0
WARNING 1
WARNING 2
NOTICE 3
NOTICE 4
INFO 5
INFO 6
INFO 7
INFO 8
INFO 9
DEBUG 10
EOF
