#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "auto-start, simple"

setup_winbind "down"

export CTDB_SERVICE_AUTOSTARTSTOP="yes"
export CTDB_MANAGED_SERVICES="foo winbind bar"

ok 'Starting service "winbind" - now managed'
simple_test

# This depends on output in the log file from the above test
ok 'Starting winbind: OK'
check_ctdb_logfile
