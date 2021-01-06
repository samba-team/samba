#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "RECORD S+ DB"

setup

do_test "RECORD" "S+" "DB"
