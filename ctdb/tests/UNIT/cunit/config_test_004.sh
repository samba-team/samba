#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

PATH="$PATH:$CTDB_SCRIPTS_TOOLS_HELPER_DIR"

setup_ctdb_base "${CTDB_TEST_TMP_DIR}" "ctdb-etc"

conffile="$CTDB_BASE/ctdb.conf"

remove_files ()
{
	rm -f "$conffile"
}

test_cleanup remove_files

cat > "$conffile" <<EOF
EOF

ok <<EOF
tcp
EOF
unit_test ctdb-config get "cluster" "transport"

ok <<EOF
EOF
unit_test ctdb-config get "cluster" "node address"

ok <<EOF
EOF
unit_test ctdb-config get "cluster" "cluster lock"

ok <<EOF
5
EOF
unit_test ctdb-config get "cluster" "leader timeout"

ok <<EOF
true
EOF
unit_test ctdb-config get "cluster" "leader capability"

cat > "$conffile" <<EOF
[cluster]
    transport = invalid
EOF

required_result 22 <<EOF
Invalid value for [cluster] -> transport = invalid
conf: validation for option "transport" failed
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

cat > "$conffile" <<EOF
[cluster]
    node address = 10.1.2.3
EOF

ok <<EOF
EOF
unit_test ctdb-config validate

cat > "$conffile" <<EOF
[cluster]
    node address = fc00:10:1:2::123
EOF

ok <<EOF
EOF
unit_test ctdb-config validate

cat > "$conffile" <<EOF
[cluster]
    node address = 10.1.2.3:123
EOF

required_result 22 <<EOF
Invalid value for [cluster] -> node address = 10.1.2.3:123
conf: validation for option "node address" failed
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

cat > "$conffile" <<EOF
[cluster]
    cluster lock = /foo/bar
EOF

required_result 0 <<EOF
EOF
unit_test ctdb-config validate

cat > "$conffile" <<EOF
[cluster]
    recovery lock = /foo/bar
EOF

required_result 0 <<EOF
Configuration option [cluster] -> recovery lock is deprecated
EOF
unit_test ctdb-config -d WARNING validate

cat > "$conffile" <<EOF
[cluster]
    leader timeout = 10
EOF

required_result 0 <<EOF
EOF
unit_test ctdb-config validate

cat > "$conffile" <<EOF
[cluster]
    leader timeout = 0
EOF

required_result 22 <<EOF
Invalid value for [cluster] -> leader timeout = 0
conf: validation for option "leader timeout" failed
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

cat > "$conffile" <<EOF
[cluster]
    leader timeout = -5
EOF

required_result 22 <<EOF
conf: invalid value [cluster] -> "leader timeout" = "-5"
Failed to load config file $conffile
EOF
unit_test ctdb-config validate

cat > "$conffile" <<EOF
[cluster]
    leader capability = false
EOF

required_result 0 <<EOF
EOF
unit_test ctdb-config validate
