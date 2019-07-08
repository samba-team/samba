#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "set to default lock file, directory is created"

setup

dir=$(dirname "$CTDB_RECOVERY_LOCK")

# Ensure directory doesn't exist before
required_result 1 ""
unit_test test -d "$dir"

# FreeBSD mkdir -v just prints the filename.  Filter the rest of the
# message from other platforms, including any exotic quotes around the
# filename.
result_filter ()
{
	sed \
		-e 's|^\(mkdir: created directory \)[[:punct:]]||' \
		-e 's|[[:punct:]]$||'
}

ok "$dir"
simple_test

# Ensure directory exists after
ok_null
unit_test test -d "$dir"
