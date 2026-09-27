#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "recovered, config file specified"

ok_null
simple_test

f="${CTDB_TEST_TMP_DIR}/smb.conf"
touch "$f"
setup_script_options <<EOF
CTDB_UPDATE_KEYTABS_SMB_CONF="$f"
EOF
ok_null
simple_test

f="${CTDB_TEST_TMP_DIR}/smb file with whitespace in name.conf"
touch "$f"
setup_script_options <<EOF
CTDB_UPDATE_KEYTABS_SMB_CONF="$f"
EOF
ok_null
simple_test
