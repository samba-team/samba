#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

pidfile=$(TMPDIR="$CTDB_TEST_TMP_DIR" mktemp)

ok_null
unit_test pidfile_test $pidfile
