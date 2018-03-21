#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "CTDB_PARTIALLY_ONLINE_INTERFACES, all down"

setup

ifaces=$(ctdb_get_interfaces)

setup_script_options <<EOF
CTDB_PARTIALLY_ONLINE_INTERFACES=yes
EOF

ethtool_interfaces_down $ifaces

msg=$(
	for i in $ifaces ; do
		echo "ERROR: No link on the public network interface $i"
	done
   )

required_result 1 "$msg"

simple_test
