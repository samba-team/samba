#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, current disconnected"

setup_nodes <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x1     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

required_result 1 <<EOF
../client/ctdb_client.c:293 Failed to connect client socket to daemon. Errno:No such file or directory(2)
../common/cmdline.c:167 Failed to connect to daemon
Failed to init ctdb
Failed to detect which PNN this node is
Is this node part of a CTDB cluster?
EOF

simple_test
