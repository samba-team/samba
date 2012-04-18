#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

cmd="$ONNODE all hostname"

define_test "$cmd" "all nodes OK"

required_result <<EOF

>> NODE: 192.168.1.101 <<
-n 192.168.1.101 hostname

>> NODE: 192.168.1.102 <<
-n 192.168.1.102 hostname

>> NODE: 192.168.1.103 <<
-n 192.168.1.103 hostname

>> NODE: 192.168.1.104 <<
-n 192.168.1.104 hostname
EOF

simple_test $cmd
