#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "by name, node 1"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0

DBMAP
0x7a19d84d locking.tdb READONLY
0x4e66c2b2 brlock.tdb STICKY
0x4d2a432b g_lock.tdb
0x7132c184 secrets.tdb PERSISTENT
0x6cf2837d registry.tdb PERSISTENT 42
0xbc57b384 ctdb-ip.tdb REPLICATED
0xbec75f0b ctdb-conn.tdb REPLICATED 23
EOF

ok <<EOF
dbid: 0x7a19d84d
name: locking.tdb
path: ${ctdbd_dbdir}/locking.tdb
PERSISTENT: no
REPLICATED: no
STICKY: no
READONLY: yes
HEALTH: OK
EOF
simple_test locking.tdb -n 1

ok <<EOF
dbid: 0x4e66c2b2
name: brlock.tdb
path: ${ctdbd_dbdir}/brlock.tdb
PERSISTENT: no
REPLICATED: no
STICKY: yes
READONLY: no
HEALTH: OK
EOF
simple_test brlock.tdb -n 1

ok <<EOF
dbid: 0x4d2a432b
name: g_lock.tdb
path: ${ctdbd_dbdir}/g_lock.tdb
PERSISTENT: no
REPLICATED: no
STICKY: no
READONLY: no
HEALTH: OK
EOF
simple_test g_lock.tdb -n 1

ok <<EOF
dbid: 0x7132c184
name: secrets.tdb
path: ${ctdbd_dbdir}/secrets.tdb
PERSISTENT: yes
REPLICATED: no
STICKY: no
READONLY: no
HEALTH: OK
EOF
simple_test secrets.tdb -n 1

ok <<EOF
dbid: 0x6cf2837d
name: registry.tdb
path: ${ctdbd_dbdir}/registry.tdb
PERSISTENT: yes
REPLICATED: no
STICKY: no
READONLY: no
HEALTH: OK
EOF
simple_test registry.tdb -n 1

ok <<EOF
dbid: 0xbc57b384
name: ctdb-ip.tdb
path: ${ctdbd_dbdir}/ctdb-ip.tdb
PERSISTENT: no
REPLICATED: yes
STICKY: no
READONLY: no
HEALTH: OK
EOF
simple_test ctdb-ip.tdb -n 1

ok <<EOF
dbid: 0xbec75f0b
name: ctdb-conn.tdb
path: ${ctdbd_dbdir}/ctdb-conn.tdb
PERSISTENT: no
REPLICATED: yes
STICKY: no
READONLY: no
HEALTH: OK
EOF
simple_test ctdb-conn.tdb -n 1

required_result 1 "No database matching 'ctdb.tdb' found"
simple_test ctdb.tdb -n 1
