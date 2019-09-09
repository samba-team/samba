#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

PATH="$PATH:$CTDB_SCRIPTS_HELPER_BINDIR"

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
true
EOF
unit_test ctdb-config get "legacy" "realtime scheduling"

ok <<EOF
true
EOF
unit_test ctdb-config get "legacy" "recmaster capability"

ok <<EOF
true
EOF
unit_test ctdb-config get "legacy" "lmaster capability"

ok <<EOF
false
EOF
unit_test ctdb-config get "legacy" "start as stopped"

ok <<EOF
false
EOF
unit_test ctdb-config get "legacy" "start as disabled"

ok <<EOF
ERROR
EOF
unit_test ctdb-config get "legacy" "script log level"

cat > "$conffile" <<EOF
[legacy]
	script log level = INVALID
EOF

required_result 22 <<EOF
Invalid value for [legacy] -> script log level = INVALID
conf: validation for option "script log level" failed
Failed to load config file ${conffile}
EOF
unit_test ctdb-config validate
