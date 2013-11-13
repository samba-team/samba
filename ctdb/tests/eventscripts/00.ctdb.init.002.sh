#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "TDB check, tdbtool does no support check"

setup_ctdb

FAKE_TDBTOOL_SUPPORTS_CHECK="no"

ok <<EOF
WARNING: The installed 'tdbtool' does not offer the 'check' subcommand.
 Using 'tdbdump' for database checks.
 Consider updating 'tdbtool' for better checks!
EOF

simple_test
