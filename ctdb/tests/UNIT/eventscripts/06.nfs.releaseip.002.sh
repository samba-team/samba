#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout causes releaseip-pre to fail"

setup

setup_nfs_callout "releaseip-pre"

required_result 1 "releaseip-pre"
simple_test
