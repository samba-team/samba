#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "nodes in config, other node is master"

setup "10.1.1.201" "eth0" <<EOF
192.168.1.1
192.168.1.2	master
192.168.1.3
EOF

ok_null
simple_test

check_ipvsadm NULL
check_lvs_ip host
