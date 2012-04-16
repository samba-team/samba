#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

cmd="$ONNODE -q all hostname"

define_test "$cmd" "all nodes OK"

required_result <<EOF
-n 192.168.1.101 hostname
-n 192.168.1.102 hostname
-n 192.168.1.103 hostname
-n 192.168.1.104 hostname
EOF

simple_test $cmd
