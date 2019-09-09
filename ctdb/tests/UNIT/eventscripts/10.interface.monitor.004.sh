#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "all interfaces up, 1 is a bond"

setup

iface=$(ctdb_get_1_interface)

setup_bond $iface

ok_null

simple_test
