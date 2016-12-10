#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, 2->3 unhealthy, all IPs assigned, NoIPTakeover"

export CTDB_TEST_LOGLEVEL=ERR

# We expect the IPs stay where they are (as opposed to
# NoIPHostOnAllDisabled).  IPs are hosted when all nodes are disabled,
# but they have nowhere else to go because of NoIPTakeover.
required_result <<EOF
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

export CTDB_SET_NoIPTakeover=1

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
