#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "CTDB_PARTIALLY_ONLINE_INTERFACES, all down"

setup_ctdb

ifaces=$(ctdb_get_interfaces)

export CTDB_PARTIALLY_ONLINE_INTERFACES="yes"

ethtool_interfaces_down $ifaces

msg=$(for i in $ifaces ; do echo "ERROR: No link on the public network interface $i" ; done)

required_result 1 "$msg"

simple_test
