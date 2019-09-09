#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"


ok_null
unit_test comm_test 1

ok_null
unit_test comm_test 2

ok "100 2048 500 4096 1024 8192 200 16384 300 32768 400 65536 1048576 "
unit_test comm_test 3
