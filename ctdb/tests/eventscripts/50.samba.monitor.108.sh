#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "port 139 down, ctdb checktcpport not implemented"

# TODO: create nmap stub
export CTDB_NOT_IMPLEMENTED="checktcpport"

setup_samba
tcp_port_down 139

required_result 1 "ERROR: samba tcp port 139 is not responding"

simple_test
