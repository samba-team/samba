#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "DB S+ RECORD"

setup

do_test "DB" "S+" "RECORD"
