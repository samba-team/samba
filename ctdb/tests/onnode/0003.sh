#!/bin/sh

. "${ONNODE_TESTS_DIR}/common.sh"

cmd="$ONNODE -p all hostname"

echo "$cmd - all nodes OK"

required_result <<EOF
[192.168.1.101] -n 192.168.1.101 hostname
[192.168.1.102] -n 192.168.1.102 hostname
[192.168.1.103] -n 192.168.1.103 hostname
[192.168.1.104] -n 192.168.1.104 hostname
EOF

simple_test -s $cmd
