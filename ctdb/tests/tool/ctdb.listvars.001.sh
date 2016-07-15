#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "weak check of output format"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

result_filter ()
{
	sed -e 's@^[A-Za-z][A-Za-z0-9]*[[:space:]]*= [0-9][0-9]*$@GOOD_LINE@' |
		sort -u
}

ok "GOOD_LINE"
simple_test
