#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "by name"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0

DBMAP
0x7a19d84d locking.tdb
0x4e66c2b2 brlock.tdb
0x4d2a432b g_lock.tdb
0x7132c184 secrets.tdb PERSISTENT
0x6cf2837d registry.tdb PERSISTENT 0x42
0xbc57b384 ctdb-ip.tdb REPLICATED
0xbec75f0b ctdb-conn.tdb REPLICATED 0x23
EOF

ok "0x0"
simple_test locking.tdb

ok "0x0"
simple_test secrets.tdb

ok "0x42"
simple_test registry.tdb

ok "0x0"
simple_test ctdb-ip.tdb

ok "0x23"
simple_test ctdb-conn.tdb
