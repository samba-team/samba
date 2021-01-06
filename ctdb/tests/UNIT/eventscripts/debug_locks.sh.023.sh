#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "RECORD S+ DB MUTEX"

setup

do_test "RECORD" "S+" "DB" "MUTEX"
