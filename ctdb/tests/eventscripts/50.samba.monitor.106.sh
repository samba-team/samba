#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "non-existent share - not checked"

setup_samba

export CTDB_SAMBA_SKIP_SHARE_CHECK="yes"

ok_null

simple_test
