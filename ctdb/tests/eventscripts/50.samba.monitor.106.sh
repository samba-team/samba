#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "non-existent share - not checked"

setup_samba
shares_missing "ERROR: samba directory \"%s\" not available" 2

export CTDB_SAMBA_SKIP_SHARE_CHECK="yes"

ok_null

simple_test
