#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

cmd="$ONNODE 4 hostname"

define_test "$cmd" "invalid pnn 4"

required_result 1 <<EOF
onnode: "node 4" does not exist
EOF

simple_test $cmd
