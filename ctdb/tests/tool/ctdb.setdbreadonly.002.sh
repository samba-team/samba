#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "set volatile non-read-only to read-only by name"

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
0x6cf2837d registry.tdb PERSISTENT 42
EOF

ok_null
simple_test locking.tdb

ok <<EOF
Number of databases:5
dbid:0x7a19d84d name:locking.tdb path:/var/run/ctdb/DB_DIR/locking.tdb.0 READONLY
dbid:0x4e66c2b2 name:brlock.tdb path:/var/run/ctdb/DB_DIR/brlock.tdb.0
dbid:0x4d2a432b name:g_lock.tdb path:/var/run/ctdb/DB_DIR/g_lock.tdb.0
dbid:0x7132c184 name:secrets.tdb path:/var/lib/ctdb/persistent/secrets.tdb.0 PERSISTENT
dbid:0x6cf2837d name:registry.tdb path:/var/lib/ctdb/persistent/registry.tdb.0 PERSISTENT
EOF

simple_test_other getdbmap
