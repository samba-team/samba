#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout causes shutdown to fail"

setup

setup_nfs_callout "shutdown"

required_result 1 "shutdown"
simple_test
