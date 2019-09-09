#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "port 139 down"

setup

tcp_port_down 139

required_result 1 "samba not listening on TCP port 139"

simple_test
