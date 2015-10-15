#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "testparm fails on 2nd time through"

setup_samba

ok_null
simple_test

export FAKE_TESTPARM_FAIL="yes"
required_result 1 <<EOF
WARNING: smb.conf cache update failed - using old cache file
Load smb config files from ${CTDB_SYS_ETCDIR}/samba/smb.conf
rlimit_max: increasing rlimit_max (2048) to minimum Windows limit (16384)
Processing section "[1_existing]"
Processing section "[2_existing]"
Processing section "[3_existing]"
Loaded services file OK.
WARNING: 'workgroup' and 'netbios name' must differ.

Failed to set smb ports
EOF
simple_test
