#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "list nodes command with bad output"

cat > "${CTDB_BASE}/ctdb.conf" <<EOF
[cluster]
	nodes list = !${CTDB_BASE}/nodes.sh
EOF
test_cleanup rm -rf "${CTDB_BASE}/ctdb.conf"

# ctdb certainly doesn't understand xml
cat > "${CTDB_BASE}/nodes.sh" <<EOF
#!/bin/sh
echo "<nodes>"
echo "<node id="0" name="192.168.20.41" />"
echo "<node id="1" name="192.168.20.42" />"
echo "</nodes>"
EOF
test_cleanup rm -rf "${CTDB_BASE}/nodes.sh"
chmod +x "${CTDB_BASE}/nodes.sh"


f="${CTDB_BASE}/nodes.sh"

required_result 1 <<EOF
Invalid node address <nodes>
${TEST_DATE_STAMP}Failed to read nodes from "!${f}"
EOF

simple_test
