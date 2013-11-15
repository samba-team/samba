#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, 2->3 unhealthy, all IPs assigned, split NoIPTakeover"

export CTDB_TEST_LOGLEVEL=0

# We expect 1/2 the IPs to move, but the rest to stay (as opposed to
# NoIPHostOnAllDisabled)
required_result <<EOF
192.168.21.254 2
192.168.21.253 0
192.168.21.252 2
192.168.20.254 0
192.168.20.253 0
192.168.20.252 2
192.168.20.251 0
192.168.20.250 2
192.168.20.249 2
EOF

export CTDB_SET_NoIPTakeover=0,1,1

simple_test 2,2,2 <<EOF
192.168.21.254 2
192.168.21.253 2
192.168.21.252 2
192.168.20.254 2
192.168.20.253 2
192.168.20.252 2
192.168.20.251 2
192.168.20.250 2
192.168.20.249 2
EOF
