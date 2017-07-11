#!/bin/sh

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_smbclient_basic.sh SERVER SERVER_IP DOMAIN USERNAME PASSWORD
EOF
exit 1;
fi

SERVER="$1"
SERVER_IP="$2"
USERNAME="$3"
PASSWORD="$4"
TARGET_ENV="$5"
shift 5
ADDARGS="$@"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
. $incdir/common_test_fns.inc

samba_bindir="$BINDIR"
samba_vlp="$samba_bindir/vlp"
samba_smbspool="$samba_bindir/smbspool"
samba_smbspool_krb5="$samba_bindir/smbspool_krb5_wrapper"

test_smbspool_noargs()
{
	cmd='$1 2>&1'
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?

	if [ $ret != 0 ]; then
		echo "$out"
		echo "failed to execute $1"
	fi

	echo "$out" | grep 'network smb "Unknown" "Windows Printer via SAMBA"'
	ret=$?
	if [ $ret != 0 ] ; then
		echo "$out"
		return 1
	fi
}

test_smbspool_authinforequired_none()
{
	cmd='$samba_smbspool_krb5 smb://$SERVER_IP/print1 200 $USERNAME "Testprint" 1 "options" $SRCDIR/testdata/printing/example.ps 2>&1'

	AUTH_INFO_REQUIRED="none"
	export AUTH_INFO_REQUIRED
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?
	unset AUTH_INFO_REQUIRED

	if [ $ret != 0 ]; then
		echo "$out"
		echo "failed to execute $smbspool_krb5"
	fi

	echo "$out" | grep 'ATTR: auth-info-required=negotiate'
	ret=$?
	if [ $ret != 0 ] ; then
		echo "$out"
		return 1
	fi
}

#
# The test enviornment uses 'vlp' (virtual lp) as the printing backend.
#
# When using the vlp backend the print job is only written to the database.
# The job needs to removed manually using 'vlp lprm' command!
#
# This calls the 'vlp' command to check if the print job has been successfully
# added to the database and also makes sure the temorary print file has been
# created.
#
# The function removes the print job from the vlp database if successful.
#
test_vlp_verify()
{
	tdbfile="$PREFIX_ABS/$TARGET_ENV/lockdir/vlp.tdb"
	if [ ! -w $tdbfile ]; then
		echo "vlp tdbfile $tdbfile doesn't exist or is not writeable!"
		return 1
	fi

	cmd='$samba_vlp tdbfile=$tdbfile lpq print1 2>&1'
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?
	if [ $ret != 0 ]; then
		echo "failed to get print queue with $samba_vlp"
		echo "$out"
	fi

	jobid=$(echo "$out" | awk '/[0-9]+/ { print $1 };')
	if [ $jobid -lt 1000 || $jobid -gt 2000 ]; then
		echo "failed to get jobid"
		echo "$out"
		return 1
	fi

	file=$(echo "$out" | awk '/[0-9]+/ { print $6 };')
	if [ ! -r $PREFIX_ABS/$TARGET_ENV/share/$file ]; then
		echo "$file doesn't exist"
		echo "$out"
		return 1
	fi

	$samba_vlp "tdbfile=$tdbfile" lprm print1 $jobid
	ret=$?
	if [ $ret != 0 ] ; then
		echo "Failed to remove jobid $jobid from $tdbfile"
		return 1
	fi
}

testit "smbspool no args" \
	test_smbspool_noargs $samba_smbspool || \
	failed=$(expr $failed + 1)

testit "smbspool_krb5_wrapper no args" \
	test_smbspool_noargs $samba_smbspool_krb5 || \
	failed=$(expr $failed + 1)

testit "smbspool_krb5_wrapper AuthInfoRequired=none" \
	test_smbspool_authinforequired_none || \
	failed=$(expr $failed + 1)

testit "smbspool print example.ps" \
	$samba_smbspool smb://$USERNAME:$PASSWORD@$SERVER_IP/print1 200 $USERNAME "Testprint" 1 "options" $SRCDIR/testdata/printing/example.ps || \
	failed=$(expr $failed + 1)

testit "vlp verify example.ps" \
	test_vlp_verify \
	|| failed=$(expr $failed + 1)

AUTH_INFO_REQUIRED="username,password"
export AUTH_INFO_REQUIRED
testit "smbspool_krb5(username,password) print example.ps" \
	$samba_smbspool_krb5 smb://$USERNAME:$PASSWORD@$SERVER_IP/print1 200 $USERNAME "Testprint" 1 "options" $SRCDIR/testdata/printing/example.ps || \
	failed=$(expr $failed + 1)

testit "vlp verify example.ps" \
	test_vlp_verify || \
	failed=$(expr $failed + 1)
unset AUTH_INFO_REQUIRED

exit $failed
