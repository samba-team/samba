#!/usr/bin/env bash
#
# Ensure we get a chdir_current_service error if CHDIR fails with EACCESS
# for an SMB2 request.
#
# BUG:https://bugzilla.samba.org/show_bug.cgi?id=14682
#
# Copyright (C) 2021 Jeremy Allison

if [ $# -lt 5 ]; then
	echo Usage: test_chdir_cache.sh \
		--configfile=SERVERCONFFILE SMBCLIENT SMBCONTROL SERVER SHARE PREFIX TESTENV
	exit 1
fi

CONF=$1
shift 1
SMBCLIENT=$1
shift 1
SMBCONTROL=$1
shift 1
SERVER=$1
shift 1
SHARE=$1
shift 1
PREFIX=${1}
shift 1
TESTENV=${1}
shift 1

# Do not let deprecated option warnings muck this up
SAMBA_DEPRECATED_SUPPRESS=1
export SAMBA_DEPRECATED_SUPPRESS

conf_dir=$(dirname ${SERVERCONFFILE})

error_inject_conf=${conf_dir}/error_inject.conf
rm -f ${error_inject_conf}

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

cd $SELFTEST_TMPDIR || exit 1

rm -f smbclient-stdin smbclient-stdout smbclient-stderr
mkfifo smbclient-stdin smbclient-stdout smbclient-stderr

CLI_FORCE_INTERACTIVE=1
export CLI_FORCE_INTERACTIVE

${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} -U${USER}%${PASSWORD} \
	<smbclient-stdin >smbclient-stdout 2>smbclient-stderr &
CLIENT_PID=$!

log_file="${PREFIX}/${TESTENV}/smbd_test.log"
# Add support for "SMBD_DONT_LOG_STDOUT=1"
if [ -r "${PREFIX}/${TESTENV}/logs/log.smbd" ]; then
	log_file="${PREFIX}/${TESTENV}/logs/log.smbd"
fi

# Count the number of chdir_current_service: vfs_ChDir.*failed: Permission denied
# errors that are already in the log (should be zero).
num_errs=$(grep "chdir_current_service: vfs_ChDir.*failed: Permission denied" ${log_file} | wc -l)

sleep 1

exec 100>smbclient-stdin 101<smbclient-stdout 102<smbclient-stderr

# consume the smbclient startup messages
head -n 1 <&101

# Do an 'ls' as ${USER} to make sure we've done a CHDIR into
# the share directory.
echo "ls" >&100

# consume the smbclient output
head -n 4 <&101

# Now change user to user2, and connect to the share.
# This should leave us in the same share directory.
echo "logon user2 ${PASSWORD}" >&100
echo "tcon ${SHARE}" >&100

# consume the smbclient output
head -n 4 <&101

# Ensure any chdir will give EACCESS.
echo "error_inject:chdir = EACCES" >${error_inject_conf}
testit "reload config 1" \
	"${SMBCONTROL}" "${CONF}" smbd reload-config ||
	failed=$((failed + 1))

sleep 1

# Do an 'ls' as user2. Changing users should have
# deleted the CHDIR cache, so we should now see
# a chdir_current_service: vfs_ChDir.*failed: Permission denied
# error message in the log.
echo 'ls' >&100

kill ${CLIENT_PID}
rm -f smbclient-stdin smbclient-stdout smbclient-stderr

# Remove the chdir inject.
rm -f ${error_inject_conf}
testit "reload config 2" \
	"${SMBCONTROL}" "${CONF}" smbd reload-config ||
	failed=$((failed + 1))

# Now look for chdir_current_service: vfs_ChDir.*failed: Permission denied
# in the smb log. There should be one more than before.

num_errs1=$(grep "chdir_current_service: vfs_ChDir.*failed: Permission denied" ${log_file} | wc -l)

testit "Verify we got at least one chdir error" \
	test $num_errs1 -gt $num_errs || failed=$(expr $failed + 1)

testok $0 $failed
