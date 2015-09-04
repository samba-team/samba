#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'false', causes monitor-pre to fail"

setup_nfs

export CTDB_NFS_CALLOUT="echo monitor-pre ; false"

required_result 1 "monitor-pre"
simple_test
