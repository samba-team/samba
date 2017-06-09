#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'false', causes takeip-pre to fail"

setup_nfs

export CTDB_NFS_CALLOUT="echo takeip-pre ; false"

required_result 1 "takeip-pre"
simple_test
