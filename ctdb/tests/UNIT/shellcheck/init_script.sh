#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "init script"

script="$CTDB_SCRIPTS_INIT_SCRIPT"

if [ -z "$script" ] ; then
	script="/etc/init.d/ctdb"
	if [ ! -r "$script" ] ; then
		script="/usr/local/etc/init.d/ctdb"
	fi
	if [ ! -r "$script" ] ; then
		ctdb_test_skip "Unable to find ctdb init script"
	fi
fi

shellcheck_test "$script"
