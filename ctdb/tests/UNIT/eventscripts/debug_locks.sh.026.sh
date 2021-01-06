#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "DB D. RECORD MUTEX"

setup

do_test "DB" "D." "RECORD" "MUTEX"
