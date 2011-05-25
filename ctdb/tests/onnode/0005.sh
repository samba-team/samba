#!/bin/sh

. "${ONNODE_TESTS_DIR}/common.sh"

cmd="$ONNODE 3 hostname"

echo "$cmd - all nodes OK"

required_result <<EOF
-n 192.168.1.104 hostname
EOF

simple_test $cmd
