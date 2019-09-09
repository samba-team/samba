#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "testparm fails on 2nd time through"

setup

ok_null
simple_test

export FAKE_TESTPARM_FAIL="yes"
required_result 1 <<EOF
WARNING: smb.conf cache update failed - using old cache file
Load smb config files from ${CTDB_SYS_ETCDIR}/samba/smb.conf
rlimit_max: increasing rlimit_max (2048) to minimum Windows limit (16384)
Processing section "[share1]"
Processing section "[share2]"
Processing section "[share3]"
Loaded services file OK.
WARNING: 'workgroup' and 'netbios name' must differ.

Failed to set smb ports
EOF
simple_test
