#!/bin/sh

. "${ONNODE_TESTS_DIR}/common.sh"

cmd="$ONNODE -v 3 hostname"

define_test "$cmd" "all nodes OK"

required_result <<EOF

>> NODE: 192.168.1.104 <<
-n 192.168.1.104 hostname
EOF

simple_test $cmd
