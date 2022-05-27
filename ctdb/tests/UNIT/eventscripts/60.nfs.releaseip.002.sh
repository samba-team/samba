#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout causes releaseip to fail"

setup

setup_nfs_callout "releaseip"

required_result 1 "releaseip"
simple_test
