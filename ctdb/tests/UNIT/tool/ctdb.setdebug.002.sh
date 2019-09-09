#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "bogus debug level integer, ensure no change"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

orig=$($CTDB -d $CTDB_DEBUGLEVEL getdebug)

required_result 1 <<EOF
Invalid debug level '42'. Valid levels are:
	ERROR | WARNING | NOTICE | INFO | DEBUG
EOF
simple_test 42

ok "$orig"
simple_test_other getdebug
