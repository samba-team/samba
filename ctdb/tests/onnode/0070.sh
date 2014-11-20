#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

cmd="$ONNODE ok hostname"

define_test "$cmd" "all nodes OK"

ctdb_set_output <<EOF
|Node|IP|Disconnected|Banned|Disabled|Unhealthy|Stopped|Inactive|PartiallyOnline|ThisNode|
|0|192.168.1.101|0|0|0|0|0|0|0|Y|
|1|192.168.1.102|0|0|0|0|0|0|0|N|
|2|192.168.1.103|0|0|0|0|0|0|0|N|
|3|192.168.1.104|0|0|0|0|0|0|0|N|
EOF

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
