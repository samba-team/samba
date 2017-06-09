#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'false', causes monitor-post to fail"

setup_nfs

export CTDB_NFS_CALLOUT="echo monitor-post ; false"

required_result 1 "monitor-post"
simple_test
