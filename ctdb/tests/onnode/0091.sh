#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

cmd="$ONNODE natgw hostname"

define_test "$cmd" "node 2 (192.168.1.103) is natgw"

ctdb_set_output <<EOF
2 192.168.1.103
:0:192.168.1.101:0:0:0:0:0:
:1:192.168.1.102:0:0:0:0:0:
:2:192.168.1.103:0:0:0:0:0:
:3:192.168.1.104:0:0:0:0:0:
EOF

required_result <<EOF
-n 192.168.1.103 hostname
EOF

simple_test $cmd
