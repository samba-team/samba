#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout causes monitor-pre to fail"

setup

setup_nfs_callout "monitor-pre"

required_result 1 "monitor-pre"
simple_test
