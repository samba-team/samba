#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

PATH="$PATH:$CTDB_SCRIPTS_TOOLS_HELPER_DIR"

setup_ctdb_base "${CTDB_TEST_TMP_DIR}" "ctdb-etc"

conffile="${CTDB_BASE}/ctdb.conf"

remove_files ()
{
	rm -f "$conffile"
}

test_cleanup remove_files

cat > "$conffile" <<EOF
EOF

ok <<EOF
ERROR
EOF
unit_test ctdb-config get "logging" "log level"

cat > "$conffile" <<EOF
[logging]
    location = syslog:magic
EOF

required_result 22 <<EOF
conf: validation for option "location" failed
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

cat > "$conffile" <<EOF
[logging]
    log level = high
EOF

required_result 22 <<EOF
conf: validation for option "log level" failed
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

cat > "$conffile" <<EOF
[logging]
    location = syslog
    log level = notice
EOF

ok_null
unit_test ctdb-config validate

ok <<EOF
syslog
EOF
unit_test ctdb-config get "logging" "location"

ok <<EOF
notice
EOF
unit_test ctdb-config get "logging" "log level"
