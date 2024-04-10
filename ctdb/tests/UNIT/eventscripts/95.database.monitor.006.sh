#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Backup directory set, several databases attached, 2 runs"

setup

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

prefix="ctdb-persistent-db-backup-$(date)"
backup_file="${backup_dir}/${prefix}.tgz"

ok <<EOF
Database backed up to foo_persistent_001.tdb.backup
Database backed up to foo_persistent_002.tdb.backup
Database backed up to foo_persistent_003.tdb.backup
Created backup tarball ${backup_file}
EOF
simple_test

# 2nd attempt does not create a backup, since previous one is too new
ok_null
simple_test
