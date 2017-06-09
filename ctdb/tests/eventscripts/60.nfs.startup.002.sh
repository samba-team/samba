#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'false', causes startup to fail"

setup_nfs

export CTDB_NFS_CALLOUT="echo startup ; false"

required_result 1 "startup"
simple_test
