#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all ok, non-default capabilities"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0	-CTDB_CAP_LMASTER
2       192.168.20.43   0x0	-CTDB_CAP_RECMASTER
EOF

# node 0

required_result 0 <<EOF
RECMASTER: YES
LMASTER: YES
EOF

simple_test -n 0

# node 1

required_result 0 <<EOF
RECMASTER: YES
LMASTER: NO
EOF

simple_test -n 1

# node 2

required_result 0 <<EOF
RECMASTER: NO
LMASTER: YES
EOF

simple_test -n 2
