#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

pidfile=$(mktemp --tmpdir="$TEST_VAR_DIR")

ok_null
unit_test pidfile_test $pidfile
