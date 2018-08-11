#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

ok_null
unit_test system_socket_test types
