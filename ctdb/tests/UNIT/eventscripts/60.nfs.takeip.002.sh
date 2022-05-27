#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout causes takeip to fail"

setup

setup_nfs_callout "takeip"

required_result 1 "takeip"
simple_test
