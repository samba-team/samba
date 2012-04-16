#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

cmd="$ONNODE con hostname"

define_test "$cmd" "1st node disconnected"

ctdb_set_output <<EOF
:Node:IP:Disconnected:Banned:Disabled:Unhealthy:Stopped:Inactive:
:0:192.168.1.101:1:0:0:0:0:0:
:1:192.168.1.102:0:0:0:0:0:0:
:2:192.168.1.103:0:0:0:0:0:0:
:3:192.168.1.104:0:0:0:0:0:0:
EOF

required_result <<EOF

>> NODE: 192.168.1.102 <<
-n 192.168.1.102 hostname

>> NODE: 192.168.1.103 <<
-n 192.168.1.103 hostname

>> NODE: 192.168.1.104 <<
-n 192.168.1.104 hostname
EOF

simple_test $cmd
