#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "list nodes command invalid"

cat > "${CTDB_BASE}/ctdb.conf" <<EOF
[cluster]
	nodes list = !${CTDB_BASE}/nodes.sh
EOF
test_cleanup rm -rf "${CTDB_BASE}/ctdb.conf"


f="${CTDB_BASE}/nodes.sh"

required_result 1 <<EOF
sys_popenv: ERROR executing command '${f}': No such file or directory
${TEST_DATE_STAMP}Failed to read nodes from "!${f}"
EOF

simple_test
