#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'false', causes releaseip-pre to fail"

setup_nfs

export CTDB_NFS_CALLOUT="echo releaseip-pre ; false"

required_result 1 "releaseip-pre"
simple_test
