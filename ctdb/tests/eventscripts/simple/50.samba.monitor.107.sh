#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "port 139 down, default tcp checker, debug"

# This has to go before the setup, otherwise it will write a dud file.
export CTDB_DEBUGLEVEL=4

setup_samba
tcp_port_down 139

required_result 1 <<EOF
ERROR: samba tcp port 139 is not responding
DEBUG: "ctdb checktcpport 139" was able to bind to port
EOF

simple_test
