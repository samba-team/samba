#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

PATH="$PATH:$CTDB_SCRIPTS_HELPER_BINDIR"

setup_ctdb_base "${CTDB_TEST_TMP_DIR}" "ctdb-etc"

conffile="${CTDB_BASE}/ctdb.conf"
scriptfile="${CTDB_BASE}/debug_locks.sh"
dbdir="${CTDB_BASE}/dbdir"
dbdir_volatile="${dbdir}/volatile"
dbdir_persistent="${dbdir}/persistent"
dbdir_state="${dbdir}/state"

remove_files ()
{
	rm -f "$conffile" "$scriptfile"
}

test_cleanup remove_files

cat > "$conffile" <<EOF
[database]
    volatile database directory = ${dbdir_volatile}
    persistent database directory = ${dbdir_persistent}
    state database directory = ${dbdir_state}
EOF

required_result 22 <<EOF
volatile database directory "${dbdir_volatile}" does not exist
conf: validation for option "volatile database directory" failed
persistent database directory "${dbdir_persistent}" does not exist
conf: validation for option "persistent database directory" failed
state database directory "${dbdir_state}" does not exist
conf: validation for option "state database directory" failed
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

mkdir -p "$dbdir_volatile"

required_result 22 <<EOF
persistent database directory "${dbdir_persistent}" does not exist
conf: validation for option "persistent database directory" failed
state database directory "${dbdir_state}" does not exist
conf: validation for option "state database directory" failed
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

mkdir -p "$dbdir_persistent"

required_result 22 <<EOF
state database directory "${dbdir_state}" does not exist
conf: validation for option "state database directory" failed
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

mkdir -p "$dbdir_state"

required_result 0 <<EOF
EOF
unit_test ctdb-config validate

ok <<EOF
EOF
unit_test ctdb-config get "database" "lock debug script"

cat > "$conffile" <<EOF
[database]
    lock debug script = $scriptfile
EOF

touch "$scriptfile"

required_result 22 <<EOF
lock debug script $scriptfile is not executable
conf: validation for option "lock debug script" failed
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

chmod +x "$scriptfile"

ok_null
unit_test ctdb-config validate

rm -f "$scriptfile"

required_result 22 <<EOF
lock debug script $scriptfile does not exist
conf: validation for option "lock debug script" failed
Failed to load config file $conffile
EOF
unit_test ctdb-config validate
