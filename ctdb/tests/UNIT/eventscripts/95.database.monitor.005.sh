#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Backup directory set, several databases attached, not leader"

setup

ctdb_set_leader 1

backup_dir="${CTDB_TEST_TMP_DIR}/backup"
mkdir "$backup_dir"

setup_date "20240101010101"

ctdb attach foo_volatile.tdb
ctdb attach foo_persistent_001.tdb persistent
ctdb attach foo_persistent_002.tdb persistent
ctdb attach foo_persistent_003.tdb persistent

setup_script_options <<EOF
CTDB_PERSISTENT_DB_BACKUP_DIR=${backup_dir}
EOF

ok_null
simple_test
