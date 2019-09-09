#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "port 445 down"

setup

tcp_port_down 445

required_result 1 "samba not listening on TCP port 445"

simple_test
