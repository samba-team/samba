#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

ok_null

unit_test db_hash_test
