#!/bin/sh
#
# Blackbox test for share with force user settings
#

if [ $# -lt 6 ]; then
cat <<EOF
Usage: test_forceuser.sh SERVER DOMAIN USERNAME PASSWORD LOCAL_PATH SMBCLIENT <smbclient arguments>
EOF
exit 1;
fi

SERVER="$1"
DOMAIN="$2"
USERNAME="force_user"
PASSWORD="$4"
LOCAL_PATH="$5"
SMBCLIENT="$6"
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
shift 6
ADDARGS="$*"
failed=0


incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh


run_cmd_nooutput() {
	CMD="$1"

	out=`eval ${CMD} > TESTOUT 2>&1`
	if [ $? != 0 ] ; then
		cat TESTOUT
		rm -f TESTOUT
		echo "command failed"
		false
		return
	fi

	rm -f TESTOUT
	true
	return
}

test_force_user_valid_users()
{
	SMB_SHARE="force_user_valid_users"
	run_cmd_nooutput "${SMBCLIENT} //${SERVER}/${SMB_SHARE} -U$USERNAME%$PASSWORD -c 'ls'"
}

# Test
testit "force user not works when combined with valid users" \
	test_force_user_valid_users || failed=`expr $failed + 1`

# Cleanup

# Results
testok $0 $failed
