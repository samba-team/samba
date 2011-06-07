#!/bin/sh

. "${ONNODE_TESTS_DIR}/common.sh"

cmd="$ONNODE 3 hostname"

define_test "$cmd" "all nodes OK"

required_result <<EOF
-n 192.168.1.104 hostname
EOF

simple_test $cmd
