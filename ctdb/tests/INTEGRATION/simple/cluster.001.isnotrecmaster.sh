#!/usr/bin/env bash

# Verify the operation of 'ctdb isnotrecmaster'

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

cmd="$CTDB isnotrecmaster || true"
try_command_on_node -v all "$cmd"

num_all_lines=$(wc -l <"$outfile")
num_rm_lines=$(grep -Fc 'this node is the recmaster' "$outfile") || true
num_not_rm_lines=$(grep -Fc 'this node is not the recmaster' "$outfile") || true

if [ $num_rm_lines -eq 1 ] ; then
    echo "OK, there is only 1 recmaster"
else
    die "BAD, there are ${num_rm_lines} nodes claiming to be the recmaster"
fi

if [ $(($num_all_lines - $num_not_rm_lines)) -eq 1 ] ; then
    echo "OK, all the other nodes claim not to be the recmaster"
else
    die "BAD, there are only ${num_not_rm_lines} notrecmaster nodes"
fi
