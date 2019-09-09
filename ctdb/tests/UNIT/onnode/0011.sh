#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

cmd="$ONNODE 99 hostname"

define_test "$cmd" "invalid pnn 99"

required_result 1 <<EOF
onnode: "node 99" does not exist
EOF

simple_test $cmd
