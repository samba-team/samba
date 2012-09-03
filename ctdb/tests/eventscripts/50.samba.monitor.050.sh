#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "auto-start, simple"

setup_samba "down"

export CTDB_SERVICE_AUTOSTARTSTOP="yes"
export CTDB_MANAGED_SERVICES="foo samba winbind bar"

ok 'Starting service "samba" - now managed'
simple_test

# This depends on output in the log file from the above test
ok 'Starting smb: OK'
check_ctdb_logfile
