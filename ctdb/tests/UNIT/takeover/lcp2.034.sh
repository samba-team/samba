#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, 1 without IP addresses"

export CTDB_TEST_LOGLEVEL=ERR

required_result <<EOF
192.168.140.4 0
192.168.140.3 1
192.168.140.2 0
192.168.140.1 1
EOF

simple_test 0,0,0 <<EOF
192.168.140.1		-1	0,1
192.168.140.2		-1	0,1
192.168.140.3		-1	0,1
192.168.140.4		-1	0,1
EOF
