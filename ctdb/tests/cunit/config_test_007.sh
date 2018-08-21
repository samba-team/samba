#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

PATH="$PATH:$CTDB_SCRIPTS_HELPER_BINDIR"

setup_ctdb_base "${TEST_VAR_DIR}" "cunit"

conffile="${CTDB_BASE}/ctdb.conf"

remove_files ()
{
	rm -f "$conffile"
}

test_cleanup remove_files

cat > "$conffile" <<EOF
EOF

ok <<EOF
false
EOF
unit_test ctdb-config get "failover" "disabled"
