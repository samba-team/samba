#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

ok_null

unit_test protocol_ctdb_compat_test 1 100
