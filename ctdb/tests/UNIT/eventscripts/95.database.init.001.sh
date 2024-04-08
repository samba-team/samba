#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "TDB check, tdbtool supports check"

setup

FAKE_TDBTOOL_SUPPORTS_CHECK="yes"

ok_null

simple_test
