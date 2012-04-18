#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

cmd="$ONNODE recmaster hostname"

define_test "$cmd" "node 1 (192.168.1.102) is recmaster"

ctdb_set_output <<EOF
1
EOF

required_result <<EOF
-n 192.168.1.102 hostname
EOF

simple_test $cmd
