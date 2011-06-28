#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "error - no args given"

setup_ctdb

iface=$(ctdb_get_1_interface)

required_result 1 "must supply interface, IP and maskbits"

simple_test
