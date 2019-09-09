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
		echo "WARNING: Unable to find ctdb init script, skipping test"
		exit 0
	fi
fi

shellcheck_test "$script"
