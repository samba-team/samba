#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "RECORD D. DB MUTEX"

setup

do_test "RECORD" "D." "DB" "MUTEX"
