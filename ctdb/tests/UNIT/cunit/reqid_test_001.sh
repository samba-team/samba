#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

output=$(
for i in $(seq 0 1023) ; do
    echo "WARNING: attempt to remove unset id $i in idtree"
done
)

ok "$output"

unit_test reqid_test
