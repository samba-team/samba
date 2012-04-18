#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "port 139 down, ctdb checktcpport/nmap/netstat not implemented"

ctdb_not_implemented "checktcpport"
export FAKE_NMAP_NOT_FOUND="yes"
export FAKE_NETSTAT_NOT_FOUND="yes"

setup_nmap_output_filter

setup_samba
tcp_port_down 139

required_result 127 <<EOF
INTERNAL ERROR: ctdb_check_ports - no working checkers in CTDB_TCP_PORT_CHECKERS="ctdb nmap netstat"
EOF

simple_test
