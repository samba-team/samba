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

# Get the default values that are dependent on install prefix
logging_location=$(ctdb-config get "logging" "location")
database_volatile_dbdir=$(ctdb-config get \
				      "database" \
				      "volatile database directory")
database_persistent_dbdir=$(ctdb-config get \
					"database" \
					"persistent database directory")
database_state_dbdir=$(ctdb-config get \
				   "database" \
				   "state database directory")

ok <<EOF
[logging]
	# location = ${logging_location}
	# log level = ERROR
[cluster]
	# transport = tcp
	# node address = 
	# recovery lock = 
[database]
	# volatile database directory = ${database_volatile_dbdir}
	# persistent database directory = ${database_persistent_dbdir}
	# state database directory = ${database_state_dbdir}
	# lock debug script = 
	# tdb mutexes = true
[event]
	# debug script = 
[failover]
	# disabled = false
[legacy]
	# realtime scheduling = true
	# recmaster capability = true
	# lmaster capability = true
	# start as stopped = false
	# start as disabled = false
	# script log level = ERROR
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
conf: unknown section for option "foobar"
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

required_result 2 <<EOF
Configuration option [section] -> "key" not defined
EOF
unit_test ctdb-config get section key

# Confirm that an unknown key doesn't stop the rest of the file from
# loading
cat > "$conffile" <<EOF
[database]
	unknown key = 123

[logging]
	log level = debug
EOF

required_error EINVAL <<EOF
conf: unknown option [database] -> "unknown key"
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

ok <<EOF
debug
EOF
unit_test ctdb-config get "logging" "log level"
