#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'true'"

setup_nfs

export CTDB_NFS_CALLOUT="true"

ok_null
simple_test
