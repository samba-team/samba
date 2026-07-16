#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Backup directory gets default mode 0700"

setup

backup_dir="${CTDB_TEST_TMP_DIR}/backup"
mkdir "$backup_dir"

setup_date "20240101010101"

ctdb attach bar_persistent.tdb persistent

setup_script_options <<EOF
CTDB_PERSISTENT_DB_BACKUP_DIR=${backup_dir}
EOF

prefix="ctdb-persistent-db-backup-$(date)"
backup_file="${backup_dir}/${prefix}.tgz"

ok <<EOF
Database backed up to bar_persistent.tdb.backup
Created backup tarball ${backup_file}
EOF
simple_test

# Verify directory permissions (default 0700)
dir_perms=$(stat -c "%a" "$backup_dir" 2>/dev/null)
if [ "$dir_perms" != "700" ]; then
	echo "ERROR: Expected directory mode 700, got ${dir_perms}"
	exit 1
fi