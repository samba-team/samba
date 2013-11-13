#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "2nd share missing"

setup_nfs

shares_missing "ERROR: nfs directory \"%s\" not available" 2

required_result 1 "$MISSING_SHARES_TEXT"

simple_test
