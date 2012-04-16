#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "non-existent share path"

setup_samba
shares_missing "ERROR: samba directory \"%s\" not available" 2

required_result 1 "$MISSING_SHARES_TEXT"

simple_test
