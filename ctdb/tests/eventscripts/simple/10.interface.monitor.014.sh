#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "spurious addresses on interface, no action"

setup_ctdb

iface=$(ctdb_get_1_interface)

ip addr add 192.168.253.253/24 dev $iface
ip addr add 192.168.254.254/24 dev $iface

ok_null

simple_test
