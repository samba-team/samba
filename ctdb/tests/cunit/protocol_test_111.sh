#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

ok_null

for i in $(seq 1 100) ; do
    unit_test protocol_ctdb_compat_test $i
done
