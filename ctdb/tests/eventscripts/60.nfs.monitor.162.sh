#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "2nd share missing, skipping share checks"

setup_nfs
export CTDB_NFS_SKIP_SHARE_CHECK="yes"

shares_missing "ERROR: nfs directory \"%s\" not available" 2

ok_null

simple_test
