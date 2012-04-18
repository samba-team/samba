#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "error - add same IP twice"

setup_ctdb

public_address=$(ctdb_get_1_public_address)
dev="${public_address%% *}"
t="${public_address#* }"
ip="${t% *}"
bits="${t#* }"

# This is a bit gross and contrived.  The method of quoting the error
# message so it makes it to required_result() is horrible.  Hopefully
# improvements will come.

err2="\
RTNETLINK answers: File exists
Failed to add $ip/$bits on dev $dev"

#EVENTSCRIPTS_TESTS_TRACE="sh -x"
iterate_test -- $public_address -- 2 "ok_null" \
    2 'required_result 1 "$err2"'
