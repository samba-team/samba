#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "nodes in config, no master (e.g. all inactive)"

setup "10.1.1.201" "eth0" <<EOF
192.168.1.1
192.168.1.2
192.168.1.3
EOF

ok_null
simple_test

check_ipvsadm NULL
check_lvs_ip host
