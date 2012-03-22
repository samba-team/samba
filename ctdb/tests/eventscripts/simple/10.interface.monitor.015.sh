#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "spurious addresses on interface, delete them"

setup_ctdb

iface=$(ctdb_get_1_interface)

ip addr add 192.168.253.253/24 dev $iface
ip addr add 192.168.254.254/24 dev $iface

export CTDB_DELETE_UNEXPECTED_IPS="yes"

ok <<EOF
WARNING: Removing unmanaged IP address 192.168.253.253/24 from interface dev123
Re-adding secondary address 192.168.254.254/24 to dev dev123
WARNING: Removing unmanaged IP address 192.168.254.254/24 from interface dev123
EOF

simple_test
