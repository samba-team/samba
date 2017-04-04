#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "by ID"

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
path: /var/run/ctdb/DB_DIR/locking.tdb.0
PERSISTENT: no
REPLICATED: no
STICKY: no
READONLY: yes
HEALTH: OK
EOF
simple_test 0x7a19d84d

ok <<EOF
dbid: 0x4e66c2b2
name: brlock.tdb
path: /var/run/ctdb/DB_DIR/brlock.tdb.0
PERSISTENT: no
REPLICATED: no
STICKY: yes
READONLY: no
HEALTH: OK
EOF
simple_test 0x4e66c2b2

ok <<EOF
dbid: 0x4d2a432b
name: g_lock.tdb
path: /var/run/ctdb/DB_DIR/g_lock.tdb.0
PERSISTENT: no
REPLICATED: no
STICKY: no
READONLY: no
HEALTH: OK
EOF
simple_test 0x4d2a432b

ok <<EOF
dbid: 0x7132c184
name: secrets.tdb
path: /var/lib/ctdb/persistent/secrets.tdb.0
PERSISTENT: yes
REPLICATED: no
STICKY: no
READONLY: no
HEALTH: OK
EOF
simple_test 0x7132c184

ok <<EOF
dbid: 0x6cf2837d
name: registry.tdb
path: /var/lib/ctdb/persistent/registry.tdb.0
PERSISTENT: yes
REPLICATED: no
STICKY: no
READONLY: no
HEALTH: OK
EOF
simple_test 0x6cf2837d

ok <<EOF
dbid: 0xbc57b384
name: ctdb-ip.tdb
path: /var/run/ctdb/DB_DIR/ctdb-ip.tdb.0
PERSISTENT: no
REPLICATED: yes
STICKY: no
READONLY: no
HEALTH: OK
EOF
simple_test 0xbc57b384

ok <<EOF
dbid: 0xbec75f0b
name: ctdb-conn.tdb
path: /var/run/ctdb/DB_DIR/ctdb-conn.tdb.0
PERSISTENT: no
REPLICATED: yes
STICKY: no
READONLY: no
HEALTH: OK
EOF
simple_test 0xbec75f0b

required_result 1 "No database matching '0xdeadc0de' found"
simple_test 0xdeadc0de
