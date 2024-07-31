#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "list nodes command valid output, but script still fails"

cat > "${CTDB_BASE}/ctdb.conf" <<EOF
[cluster]
	nodes list = !${CTDB_BASE}/nodes.sh
EOF
test_cleanup rm -rf "${CTDB_BASE}/ctdb.conf"

cat > "${CTDB_BASE}/nodes.sh" <<EOF
#!/bin/sh
for x in 41 42 43; do
	echo 192.168.20.\$x
done
exit 2
EOF
test_cleanup rm -rf "${CTDB_BASE}/nodes.sh"
chmod +x "${CTDB_BASE}/nodes.sh"


f="${CTDB_BASE}/nodes.sh"

required_result 0 <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

simple_test
