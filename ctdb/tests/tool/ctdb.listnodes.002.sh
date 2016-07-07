#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "missing nodes file"

setup_nodes <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

required_result 0 <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

simple_test
