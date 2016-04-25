#!/bin/sh

# this runs a smbclient based authentication tests

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_smbclient_ntlm.sh SERVER USERNAME PASSWORD MAPTOGUEST SMBCLIENT <smbclient arguments>
EOF
exit 1;
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"
MAPTOGUEST="$4"
SMBCLIENT="$5"
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
shift 5
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

testit "smbclient username.password.NT1OLD" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U$USERNAME%$PASSWORD -mNT1 --option=clientusespnego=no --option=clientntlmv2auth=no -c quit $ADDARGS
testit "smbclient username.password.NT1NEW" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U$USERNAME%$PASSWORD -mNT1 -c quit $ADDARGS
testit "smbclient username.password.SMB3" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U$USERNAME%$PASSWORD -mSMB3 -c quit $ADDARGS

testit "smbclient anonymous.nopassword.NT1OLD" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U% -mNT1 --option=clientusespnego=no --option=clientntlmv2auth=no -c quit $ADDARGS
testit "smbclient anonymous.nopassword.NT1NEW" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U% -mNT1 -c quit $ADDARGS
testit "smbclient anonymous.nopassword.SMB3" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U% -mSMB3 -c quit $ADDARGS
if test x"${MAPTOGUEST}" = x"never" ; then
	testit_expect_failure "smbclient anonymous.badpassword.NT1NEW.fail" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U%badpassword -mNT1 -c quit $ADDARGS
	testit_expect_failure "smbclient anonymous.badpassword.SMB3.fail" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U%badpassword -mSMB3 -c quit $ADDARGS
else
	testit "smbclient anonymous.badpassword.NT1NEW.guest" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U%badpassword -mNT1 -c quit $ADDARGS
	testit "smbclient anonymous.badpassword.SMB3.guest" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U%badpassword -mSMB3 -c quit $ADDARGS

	testit "smbclient baduser.badpassword.NT1NEW.guest" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -Ubaduser%badpassword -mNT1 -c quit $ADDARGS
	testit "smbclient baduser.badpassword.SMB3.guest" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -Ubaduser%badpassword -mSMB3 -c quit $ADDARGS
fi
