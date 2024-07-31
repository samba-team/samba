#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, nodes list command"

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
EOF
test_cleanup rm -rf "${CTDB_BASE}/nodes.sh"
chmod +x "${CTDB_BASE}/nodes.sh"

setup_ctdbd <<EOF
USENODESCOMMAND
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

ok <<EOF
No change in nodes file, skipping unnecessary reload
EOF

simple_test
