#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout succeeds"

setup

setup_nfs_callout

ok_null
simple_test
