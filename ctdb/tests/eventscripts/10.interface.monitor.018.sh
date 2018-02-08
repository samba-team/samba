#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "VLAN on bond, active slaves, link down"

setup

iface=$(ctdb_get_1_interface)

bond="bond0"

setup_bond "$bond" "" "down"

ip link add link "$bond" name "$iface" type vlan id 11
ip link set "${iface}@${bond}" up

required_result 1 "ERROR: public network interface ${bond} is down"

simple_test
