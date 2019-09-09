#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "setup, no tunables in config"

setup

ok_null

simple_test
