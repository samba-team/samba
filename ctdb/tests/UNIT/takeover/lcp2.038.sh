#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, balanced, 1 IP hosted by 2 nodes, counts as changed"

export CTDB_TEST_LOGLEVEL=ERR

required_result <<EOF
192.168.20.254 2
192.168.20.253 1
192.168.20.252 0
192.168.20.251 2
192.168.20.250 1
192.168.20.249 0
Changed IPs: 1
EOF

# Node 0 still hosts 192.168.20.254, which has moved to node 2.  It
# must be released from node 0, so it has changed, even though the
# allocation result is the same.

simple_test 0,0,0 multi num_changed <<EOF
192.168.20.249 0
192.168.20.250 1
192.168.20.251 2
192.168.20.252 0
192.168.20.253 1
192.168.20.254 0

192.168.20.249 0
192.168.20.250 1
192.168.20.251 2
192.168.20.252 0
192.168.20.253 1
192.168.20.254 2

192.168.20.249 0
192.168.20.250 1
192.168.20.251 2
192.168.20.252 0
192.168.20.253 1
192.168.20.254 2
EOF
