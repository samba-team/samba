#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "all interfaces up, 1 is a bond"

setup_ctdb

iface=$(ctdb_get_1_interface)

setup_bond $iface

ok_null

simple_test
