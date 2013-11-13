#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "port 139 down, default tcp checker, debug"

export CTDB_SCRIPT_DEBUGLEVEL=4

setup_samba
tcp_port_down 139

required_result 1 <<EOF
ERROR: samba tcp port 139 is not responding
DEBUG: "ctdb checktcpport 139" was able to bind to port
EOF

simple_test
