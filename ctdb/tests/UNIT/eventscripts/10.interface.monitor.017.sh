#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 VLAN, link down"

setup

iface=$(ctdb_get_1_interface)

ethtool_interfaces_down "$iface"

# This just exercises the VLAN checking code, which will allow us to
# determine that real0 is not a bond.
realiface="real0"
ip link add link "$realiface" name "$iface" type vlan id 11
ip link set "${iface}@${realiface}" up

required_result 1 "ERROR: No link on the public network interface ${iface}"
simple_test
