#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "CTDB_PARTIALLY_ONLINE_INTERFACES, 1 bond down"

setup_ctdb

ifaces=$(ctdb_get_interfaces)

for i in $ifaces ; do
    setup_bond $i "None"
done

export CTDB_PARTIALLY_ONLINE_INTERFACES="yes"

ethtool_interfaces_down $ifaces

msg=$(for i in $ifaces ; do echo "ERROR: No active slaves for bond device $i" ; done)

required_result 1 "$msg"

simple_test
