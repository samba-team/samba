#!/bin/sh
#
# Blackbox tests for smbpasswd
#
# Copyright (c) 2015-2016 Andreas Schneider <asn@samba.org>
#

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_smbpasswd.sh SERVER USERNAME PASSWORD
EOF
exit 1;
fi

SERVER=$1
SERVER_IP=$2
USERNAME=$3
PASSWORD=$4
shift 4

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

samba_bindir="$BINDIR"
samba_srcdir="$SRCDIR"

samba_texpect="$samba_bindir/texpect"
samba_smbpasswd="$samba_bindir/smbpasswd"

samba_test_user="alice_smbpasswd"
samba_test_user_pwd="Secret007"
samba_test_user_new_pwd="Secret008"

create_local_smb_user()
{
	user=$1
	password=$2

	tmpfile=$PREFIX/smbpasswd_create_user_script
	cat > $tmpfile <<EOF
expect New SMB password:
send $password\n
expect Retype new SMB password:
send $password\n
EOF

	cmd='UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $samba_texpect $tmpfile $samba_smbpasswd -c $SMB_CONF_PATH -a $user 2>&1'
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?

	rm -f $tmpfile

	if [ $ret -ne 0 ]; then
		echo "Failed to create smb user $user"
		return 1
	fi

	getent passwd $user
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Failed to create smb user $user"
		return 1
	fi
}

delete_local_smb_user()
{
	user=$1

	# This also deletes the unix account!
	UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $samba_smbpasswd -c $SMB_CONF_PATH -x $user
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Failed to delete smb user $user"
		return 1
	fi
}

test_smbpasswd()
{
	user=$1
	oldpwd=$2
	newpwd=$3

	user_id=$(id -u $user)

	tmpfile=$PREFIX/smbpasswd_change_password_script
	cat > $tmpfile <<EOF
expect Old SMB password:
send $oldpwd\n
expect New SMB password:
send $newpwd\n
expect Retype new SMB password:
send $newpwd\n
EOF

	cmd='UID_WRAPPER_INITIAL_RUID=$user_id UID_WRAPPER_INITIAL_EUID=$user_id $samba_texpect $tmpfile $samba_smbpasswd -c $SMB_CONF_PATH -r $SERVER 2>&1'
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?
	rm -f $tmpfile
	if [ $ret -ne 0 ]; then
		echo "Failed to change user password $user"
		return 1
	fi

	prompt="Password changed for user $user"
	echo "$out" | grep "$prompt" >/dev/null 2>&1
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Failed to change password for user $user"
		echo "$out"
		return 1
	fi
}

testit "Create user $samba_test_user" \
	create_local_smb_user $samba_test_user $samba_test_user_pwd \
	|| failed=$(expr $failed + 1)

testit "Change user password" \
	test_smbpasswd $samba_test_user $samba_test_user_pwd $samba_test_user_new_pwd \
	|| failed=$(expr $failed + 1)

testit "Delete user $samba_test_user" \
	delete_local_smb_user $samba_test_user \
	|| failed=$(expr $failed + 1)

exit $failed
