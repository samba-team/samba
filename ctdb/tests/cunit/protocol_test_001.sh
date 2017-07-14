#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

ok_null

for i in $(seq 1 1000) ; do
    unit_test protocol_basic_test $i
done
