#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "simple ping"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

result_filter ()
{
    sed -e "s@=[.0-9]* sec@=NUM sec@"
}


ok <<EOF
response from 0 time=NUM sec  (1 clients)
EOF

simple_test
