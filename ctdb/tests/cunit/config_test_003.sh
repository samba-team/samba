#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

PATH="$PATH:$CTDB_SCRIPTS_TOOLS_HELPER_DIR"

setup_ctdb_base "${CTDB_TEST_TMP_DIR}" "ctdb-etc"

conffile="${CTDB_BASE}/ctdb.conf"
scriptfile="${CTDB_BASE}/debug-hung-script.sh"

remove_files ()
{
	rm -f "$conffile"
}

test_cleanup remove_files

cat > "$conffile" <<EOF
EOF

ok <<EOF
EOF
unit_test ctdb-config get "event" "debug script"

cat > "$conffile" <<EOF
[event]
    debug script = debug-hung-script.sh
EOF

touch "$scriptfile"

required_result 22 <<EOF
debug script $scriptfile is not executable
conf: validation for option "debug script" failed
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

chmod +x "$scriptfile"

ok_null
unit_test ctdb-config validate

rm -f "$scriptfile"

required_result 22 <<EOF
debug script $scriptfile does not exist
conf: validation for option "debug script" failed
Failed to load config file $conffile
EOF
unit_test ctdb-config validate
