#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "error - add same IP twice"

setup

public_address=$(ctdb_get_1_public_address)
dev="${public_address%% *}"
t="${public_address#* }"
ip="${t% *}"
bits="${t#* }"

ok_null
simple_test $public_address

required_result 1 <<EOF
RTNETLINK answers: File exists
Failed to add $ip/$bits on dev $dev
EOF
simple_test $public_address
