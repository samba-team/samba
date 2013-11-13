#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "port 445 down"

setup_samba
tcp_port_down 445

required_result 1 "ERROR: samba tcp port 445 is not responding"

simple_test
