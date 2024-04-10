#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Backup directory set, no persistent databases attached"

setup

backup_dir="${CTDB_TEST_TMP_DIR}/backup"
mkdir "$backup_dir"

setup_date "20240101010101"

ctdb attach foo_volatile.tdb

setup_script_options <<EOF
CTDB_PERSISTENT_DB_BACKUP_DIR=${backup_dir}
EOF

prefix="ctdb-persistent-db-backup-$(date)"
backup_file="${backup_dir}/${prefix}.tgz"

ok <<EOF
Created backup tarball ${backup_file}
EOF
simple_test

ok <<EOF
${prefix}/
EOF
simple_test_command tar -t -f "$backup_file"
