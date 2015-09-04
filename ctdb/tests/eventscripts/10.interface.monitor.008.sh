#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "unknown interface, down, up"

setup_ctdb

iface="dev999"
export CTDB_PUBLIC_INTERFACE="$iface"

ethtool_interfaces_down "$iface"
required_result 1 "ERROR: No link on the public network interface $iface"
simple_test

ethtool_interfaces_up "$iface"
ok_null
simple_test

ok_null
simple_test
