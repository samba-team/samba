#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout causes takeip-pre to fail"

setup

setup_nfs_callout "takeip-pre"

required_result 1 "takeip-pre"
simple_test
