#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "RECORD S+ RECORD"

setup

do_test "RECORD" "S+" "RECORD"
