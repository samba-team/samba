#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "auto-stop, simple"

setup_samba

export CTDB_SERVICE_AUTOSTARTSTOP="yes"
export CTDB_MANAGED_SERVICES="foo"
unset CTDB_MANAGES_SAMBA

ok 'Stopping service "samba" - no longer managed'
simple_test

# This depends on output in the log file from the above test
ok 'Stopping smb: OK'
check_ctdb_logfile
