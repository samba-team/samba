#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Backup directory gets custom mode 0711"

setup

backup_dir="${CTDB_TEST_TMP_DIR}/backup"
mkdir "$backup_dir"

setup_date "20240101010101"

ctdb attach foo_persistent.tdb persistent

setup_script_options <<EOF
CTDB_PERSISTENT_DB_BACKUP_DIR=${backup_dir}
CTDB_PERSISTENT_DB_BACKUP_MODE=0711
EOF

prefix="ctdb-persistent-db-backup-$(date)"
backup_file="${backup_dir}/${prefix}.tgz"

ok <<EOF
Database backed up to foo_persistent.tdb.backup
Created backup tarball ${backup_file}
EOF
simple_test
# Verify directory permissions were set to 0711
dir_perms=$(stat -c "%a" "$backup_dir" 2>/dev/null)
if [ "$dir_perms" != "711" ]; then
	echo "ERROR: Expected directory mode 711, got ${dir_perms}"
	exit 1
fi