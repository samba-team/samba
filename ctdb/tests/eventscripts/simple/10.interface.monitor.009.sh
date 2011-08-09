#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "CTDB_PARTIALLY_ONLINE_INTERFACES, 1 down"

setup_ctdb

iface=$(ctdb_get_1_interface)

export CTDB_PARTIALLY_ONLINE_INTERFACES="yes"

ethtool_interfaces_down "$iface"

ok "ERROR: No link on the public network interface $iface"

simple_test
