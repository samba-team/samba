#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'false', causes shutdown to fail"

setup_nfs

export CTDB_NFS_CALLOUT="echo shutdown ; false"

required_result 1 "shutdown"
simple_test
