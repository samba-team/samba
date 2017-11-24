#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

ok_null
unit_test protocol_util_test
