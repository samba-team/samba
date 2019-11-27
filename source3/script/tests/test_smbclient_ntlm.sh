#!/bin/sh

# this runs a smbclient based authentication tests

if [ $# -lt 6 ]; then
cat <<EOF
Usage: test_smbclient_ntlm.sh SERVER USERNAME PASSWORD MAPTOGUEST SMBCLIENT PROTOCOL <smbclient arguments>
EOF
exit 1;
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"
MAPTOGUEST="$4"
SMBCLIENT="$5"
PROTOCOL="$6"
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
shift 6
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

if [ $PROTOCOL != "SMB3" -a $PROTOCOL != "NT1" ]; then
cat <<EOF
Uexpected protocol specified $PROTOCOL
EOF
	exit 1;
fi

if [ $PROTOCOL = "NT1" ]; then
	testit "smbclient username.password.NT1OLD" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U$USERNAME%$PASSWORD -mNT1 --option=clientusespnego=no --option=clientntlmv2auth=no -c quit $ADDARGS
	testit "smbclient username.password.NT1NEW" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U$USERNAME%$PASSWORD -mNT1 -c quit $ADDARGS
fi
if [ $PROTOCOL = "SMB3" ]; then
	testit "smbclient username.password.SMB3" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U$USERNAME%$PASSWORD -mSMB3 -c quit $ADDARGS
fi

if [ $PROTOCOL = "NT1" ]; then
	testit "smbclient anonymous.nopassword.NT1OLD" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U% -mNT1 --option=clientusespnego=no --option=clientntlmv2auth=no -c quit $ADDARGS
	testit "smbclient anonymous.nopassword.NT1NEW" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U% -mNT1 -c quit $ADDARGS
fi
if [ $PROTOCOL = "SMB3" ]; then
	testit "smbclient anonymous.nopassword.SMB3" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U% -mSMB3 -c quit $ADDARGS
fi
if test x"${MAPTOGUEST}" = x"never" ; then
	if [ $PROTOCOL = "NT1" ]; then
		testit_expect_failure "smbclient anonymous.badpassword.NT1NEW.fail" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U%badpassword -mNT1 -c quit $ADDARGS
	fi
	if [ $PROTOCOL = "SMB3" ]; then
		testit_expect_failure "smbclient anonymous.badpassword.SMB3.fail" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U%badpassword -mSMB3 -c quit $ADDARGS
	fi
else
	if [ $PROTOCOL = "NT1" ]; then
		testit "smbclient anonymous.badpassword.NT1NEW.guest" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U%badpassword -mNT1 -c quit $ADDARGS
	fi
	if [ $PROTOCOL = "SMB3" ]; then
		testit "smbclient anonymous.badpassword.SMB3.guest" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -U%badpassword -mSMB3 -c quit $ADDARGS
	fi

	if [ $PROTOCOL = "NT1" ]; then
		testit "smbclient baduser.badpassword.NT1NEW.guest" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -Ubaduser%badpassword -mNT1 -c quit $ADDARGS
	fi
	if [ $PROTOCOL = "SMB3" ]; then
		testit "smbclient baduser.badpassword.SMB3.guest" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -Ubaduser%badpassword -mSMB3 -c quit $ADDARGS
	fi
	if [ $PROTOCOL = "NT1" ]; then
		testit_expect_failure "smbclient baduser.badpassword.NT1OLD.signfail" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -Ubaduser%badpassword -mNT1 --option=clientusespnego=no --option=clientntlmv2auth=no --signing=required -c quit $ADDARGS
		testit_expect_failure "smbclient baduser.badpassword.NT1NEW.signfail" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -Ubaduser%badpassword -mNT1 --signing=required -c quit $ADDARGS
	fi
	if [ $PROTOCOL = "SMB3" ]; then
		testit_expect_failure "smbclient baduser.badpassword.SMB3.signfail" $SMBCLIENT //$SERVER/IPC\$ $CONFIGURATION -Ubaduser%badpassword -mSMB3 --signing=required -c quit $ADDARGS
	fi
fi
