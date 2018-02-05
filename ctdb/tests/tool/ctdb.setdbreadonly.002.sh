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
0xbc57b384 ctdb-ip.tdb REPLICATED
0xbec75f0b ctdb-conn.tdb REPLICATED 23
EOF

ok_null
simple_test locking.tdb

ok <<EOF
Number of databases:7
dbid:0x7a19d84d name:locking.tdb path:${ctdbd_dbdir}/locking.tdb READONLY
dbid:0x4e66c2b2 name:brlock.tdb path:${ctdbd_dbdir}/brlock.tdb
dbid:0x4d2a432b name:g_lock.tdb path:${ctdbd_dbdir}/g_lock.tdb
dbid:0x7132c184 name:secrets.tdb path:${ctdbd_dbdir}/secrets.tdb PERSISTENT
dbid:0x6cf2837d name:registry.tdb path:${ctdbd_dbdir}/registry.tdb PERSISTENT
dbid:0xbc57b384 name:ctdb-ip.tdb path:${ctdbd_dbdir}/ctdb-ip.tdb REPLICATED
dbid:0xbec75f0b name:ctdb-conn.tdb path:${ctdbd_dbdir}/ctdb-conn.tdb REPLICATED
EOF

simple_test_other getdbmap
