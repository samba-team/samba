#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "volatile traverse"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

ok_null
simple_test_other attach "volatile.tdb"

for i in $(seq 1 9) ; do
    ok_null
    simple_test_other writekey "volatile.tdb" "key$i" "value$i"
done

ok <<EOF
key(4) = "key2"
dmaster: 0
rsn: 0
flags: 0x00000000
data(6) = "value2"

key(4) = "key4"
dmaster: 0
rsn: 0
flags: 0x00000000
data(6) = "value4"

key(4) = "key9"
dmaster: 0
rsn: 0
flags: 0x00000000
data(6) = "value9"

key(4) = "key8"
dmaster: 0
rsn: 0
flags: 0x00000000
data(6) = "value8"

key(4) = "key6"
dmaster: 0
rsn: 0
flags: 0x00000000
data(6) = "value6"

key(4) = "key3"
dmaster: 0
rsn: 0
flags: 0x00000000
data(6) = "value3"

key(4) = "key7"
dmaster: 0
rsn: 0
flags: 0x00000000
data(6) = "value7"

key(4) = "key5"
dmaster: 0
rsn: 0
flags: 0x00000000
data(6) = "value5"

key(4) = "key1"
dmaster: 0
rsn: 0
flags: 0x00000000
data(6) = "value1"

Dumped 9 records
EOF

simple_test "volatile.tdb"
