#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "ctdbd_wrapper"

shellcheck_test "${CTDB_SCRIPTS_SBIN_DIR}/ctdbd_wrapper"
