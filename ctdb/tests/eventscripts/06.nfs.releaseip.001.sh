#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'true'"

setup

CTDB_NFS_CALLOUT="true"

ok_null
simple_test
