#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "attach replicated database"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

ok_null
simple_test "replicated.tdb" replicated

ok <<EOF
Number of databases:1
dbid:0x84241f7c name:replicated.tdb path:${ctdbd_dbdir}/replicated.tdb REPLICATED
EOF

simple_test_other getdbmap

ok <<EOF
dbid: 0x84241f7c
name: replicated.tdb
path: ${ctdbd_dbdir}/replicated.tdb
PERSISTENT: no
REPLICATED: yes
STICKY: no
READONLY: no
HEALTH: OK
EOF

simple_test_other getdbstatus "replicated.tdb"
