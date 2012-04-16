#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "error - remove a non-existent ip"

setup_ctdb

public_address=$(ctdb_get_1_public_address)
ip="${public_address% *}" ; ip="${ip#* }"

required_result 1 <<EOF
RTNETLINK answers: Cannot assign requested address
Failed to del ${ip} on dev ${public_address%% *}
EOF

simple_test $public_address
