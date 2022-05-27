#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout causes monitor-post to fail"

setup

setup_nfs_callout "monitor-post"

required_result 1 "monitor-post"
simple_test
