#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "unknown interface, down, up"

setup_ctdb

iface="dev999"
export CTDB_PUBLIC_INTERFACE="$iface"

#EVENTSCRIPTS_TESTS_TRACE="sh -x"
iterate_test 3 "ok_null" \
    1 'ethtool_interfaces_down "$iface" ; required_result 1 "ERROR: No link on the public network interface $iface"' \
    2 'ethtool_interfaces_up "$iface"'
