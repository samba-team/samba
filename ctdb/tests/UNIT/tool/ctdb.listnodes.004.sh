#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "list nodes command fails"

cat > "${CTDB_BASE}/ctdb.conf" <<EOF
[cluster]
	nodes list = !${CTDB_BASE}/nodes.sh
EOF
test_cleanup rm -rf "${CTDB_BASE}/ctdb.conf"

cat > "${CTDB_BASE}/nodes.sh" <<EOF
#!/bin/sh
echo "error: foo" >&2
exit 1
EOF
test_cleanup rm -rf "${CTDB_BASE}/nodes.sh"
chmod +x "${CTDB_BASE}/nodes.sh"


f="${CTDB_BASE}/nodes.sh"

required_result 1 <<EOF
error: foo
${TEST_DATE_STAMP}Failed to read nodes from "!${f}"
EOF

simple_test
