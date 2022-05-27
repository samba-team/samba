#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout causes startup to fail"

setup

setup_nfs_callout "startup"

required_result 1 "startup"
simple_test
