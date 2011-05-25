#!/bin/sh

. "${ONNODE_TESTS_DIR}/common.sh"

cmd="$ONNODE recmaster hostname"

echo "$cmd - node 1 (192.168.1.102) is recmaster"

ctdb_set_output <<EOF
1
EOF

required_result <<EOF
-n 192.168.1.102 hostname
EOF

simple_test $cmd
