#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

PATH="$PATH:$CTDB_SCRIPTS_TOOLS_HELPER_DIR"

setup_ctdb_base "${TEST_VAR_DIR}" "cunit"

conffile="${CTDB_BASE}/ctdb.conf"

remove_files ()
{
	rm -f "$conffile"
}

test_cleanup remove_files

# Get the default values that are dependent on install prefix
logging_location=$(ctdb-config get "logging" "location")

ok <<EOF
[logging]
	# location = ${logging_location}
	# log level = ERROR
[cluster]
	# transport = tcp
	# node address = 
	# recovery lock = 
[event]
	# debug script = 
EOF
unit_test ctdb-config dump

required_result 2 <<EOF
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

cat > "$conffile" <<EOF
EOF

ok_null
unit_test ctdb-config validate

cat > "$conffile" <<EOF
[foobar]
EOF

required_result 22 <<EOF
conf: unknown section [foobar]
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

cat > "$conffile" <<EOF
foobar = cat
EOF

required_result 22 <<EOF
conf: unknown option "foobar"
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

required_result 2 <<EOF
Configuration option [section] -> "key" not defined
EOF
unit_test ctdb-config get section key
