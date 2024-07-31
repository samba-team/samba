#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "list nodes command with argument"

cat > "${CTDB_BASE}/ctdb.conf" <<EOF
[cluster]
	nodes list = !/usr/bin/printf %s\\n%s\\n 192.168.20.41 192.168.20.42
EOF
test_cleanup rm -rf "${CTDB_BASE}/ctdb.conf"

required_result 0 <<EOF
192.168.20.41
192.168.20.42
EOF

simple_test
