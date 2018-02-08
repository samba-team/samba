#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Check public IP dropping, none assigned"

setup

ok_null

simple_test
