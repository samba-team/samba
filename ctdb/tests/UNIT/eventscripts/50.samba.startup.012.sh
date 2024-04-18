#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "startup, with interfaces list generation"

setup

interfaces_file="${CTDB_TEST_TMP_DIR}/interfaces.conf"

setup_script_options <<EOF
CTDB_SAMBA_INTERFACES_FILE=${interfaces_file}
CTDB_SAMBA_INTERFACES_EXTRA='"devX123;options=nodynamic" "devX456;options=dynamic"'
EOF

ok <<EOF
Starting smb: OK
EOF
simple_test

ok <<EOF
    bind interfaces only = yes
    interfaces = lo  "dev123;options=dynamic" "dev456;options=dynamic" "devX123;options=nodynamic" "devX456;options=dynamic"
EOF
simple_test_command cat "$interfaces_file"
