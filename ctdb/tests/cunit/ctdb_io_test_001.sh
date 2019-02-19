#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

ok_null

unit_test ctdb_io_test 1
unit_test ctdb_io_test 2
