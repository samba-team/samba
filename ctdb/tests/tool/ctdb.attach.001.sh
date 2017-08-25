#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "attach volatile database"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

ok_null
simple_test "volatile.tdb"

ok <<EOF
Number of databases:1
dbid:0x211bf47b name:volatile.tdb path:${ctdbd_dbdir}/volatile.tdb
EOF

simple_test_other getdbmap

ok <<EOF
dbid: 0x211bf47b
name: volatile.tdb
path: ${ctdbd_dbdir}/volatile.tdb
PERSISTENT: no
REPLICATED: no
STICKY: no
READONLY: no
HEALTH: OK
EOF

simple_test_other getdbstatus "volatile.tdb"
