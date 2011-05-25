#!/bin/sh

. "${ONNODE_TESTS_DIR}/common.sh"

cmd="$ONNODE -pq all hostname"

echo "$cmd - all nodes OK"

required_result <<EOF
-n 192.168.1.101 hostname
-n 192.168.1.102 hostname
-n 192.168.1.103 hostname
-n 192.168.1.104 hostname
EOF

simple_test -s $cmd
