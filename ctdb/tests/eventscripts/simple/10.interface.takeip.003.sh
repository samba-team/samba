#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "error - add same IP twice"

setup_ctdb

public_address=$(ctdb_get_1_public_address)

# This is a bit gross and contrived.  The method of quoting the error
# message so it makes it to required_result() is horrible.  Hopefully
# improvements will come.

err2="\
RTNETLINK answers: File exists
Failed to add 10.0.0.1/24 on dev dev123"

#EVENTSCRIPTS_TESTS_TRACE="sh -x"
iterate_test -- $public_address -- 2 "ok_null" \
    2 'required_result 1 "$err2"'
