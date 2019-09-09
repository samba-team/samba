#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, current disconnected"

setup_nodes <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

# Don't setup ctdbd - disconnected on current node
#setup_ctdbd <<EOF
#NODEMAP
#0       192.168.20.41   0x1     CURRENT RECMASTER
#1       192.168.20.42   0x0
#2       192.168.20.43   0x0
#EOF

required_result 1 <<EOF
connect() failed, errno=2
Failed to connect to CTDB daemon ($ctdbd_socket)
Failed to detect PNN of the current node.
Is this node part of CTDB cluster?
EOF

simple_test
