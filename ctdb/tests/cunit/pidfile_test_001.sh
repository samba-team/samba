#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

pidfile=$(TMPDIR="$TEST_VAR_DIR" mktemp)

ok_null
unit_test pidfile_test $pidfile
