#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "1 interface down"

setup_ctdb

iface=$(ctdb_get_1_interface)

ethtool_interfaces_down $iface

required_result 1 "ERROR: No link on the public network interface $iface"

simple_test
