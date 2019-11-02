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
samba_argv_wrapper="$samba_bindir/smbspool_argv_wrapper"
samba_smbtorture3="$samba_bindir/smbtorture3"
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
	cmd='$samba_smbspool_krb5 smb://$SERVER_IP/print4 200 $USERNAME "Testprint" 1 "options" $SRCDIR/testdata/printing/example.ps 2>&1'

	AUTH_INFO_REQUIRED="none"
	export AUTH_INFO_REQUIRED
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?
	unset AUTH_INFO_REQUIRED

	if [ $ret != 0 ]; then
		echo "$out"
		echo "failed to execute $smbspool_krb5"
		return 1
	fi

	return 0
}

test_smbspool_authinforequired_unknown()
{
	cmd='$samba_smbspool_krb5 smb://$SERVER_IP/print4 200 $USERNAME "Testprint" 1 "options" $SRCDIR/testdata/printing/example.ps 2>&1'

	# smbspool_krb5_wrapper must ignore AUTH_INFO_REQUIRED unknown to him and pass the task to smbspool
	# smbspool must fail with NT_STATUS_ACCESS_DENIED (22)
	# "jjf4wgmsbc0" is just a random string
	AUTH_INFO_REQUIRED="jjf4wgmsbc0"
	export AUTH_INFO_REQUIRED
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?
	unset AUTH_INFO_REQUIRED

	case "$ret" in
		2 ) return 0 ;;
		* )
			echo "ret=$ret"
			echo "$out"
			echo "failed to test $smbspool_krb5 against unknown value of AUTH_INFO_REQUIRED"
			return 1
		;;
	esac
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
	if [ -z "$jobid" ] || [ $jobid -lt 100 || [ $jobid -gt 2000 ]; then
		echo "Invalid jobid: $jobid"
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

test_delete_on_close()
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
		echo "failed to lpq jobs on print1 with $samba_vlp"
		echo "$out"
		return 1
	fi

	num_jobs=$(echo "$out" | wc -l)
	#
	# Now run the test DELETE-PRINT from smbtorture3
	#
	cmd='$samba_smbtorture3 //$SERVER_IP/print1 -U$USERNAME%$PASSWORD DELETE-PRINT 2>&1'
	eval echo "$cmd"
	out_t=$(eval $cmd)
	ret=$?
	if [ $ret != 0 ]; then
		echo "failed to run DELETE-PRINT on print1"
		echo "$out_t"
		return 1
	fi

	cmd='$samba_vlp tdbfile=$tdbfile lpq print1 2>&1'
	eval echo "$cmd"
	out1=$(eval $cmd)
	ret=$?
	if [ $ret != 0 ]; then
		echo "(2) failed to lpq jobs on print1 with $samba_vlp"
		echo "$out1"
		return 1
	fi
	num_jobs1=$(echo "$out1" | wc -l)

	#
	# Number of jobs should not change. Job
	# should not have made it to backend.
	#
	if [ "$num_jobs1" -ne "$num_jobs" ]; then
		echo "delete-on-close fail $num_jobs1 -ne $num_jobs"
		echo "$out"
		echo "$out_t"
		echo "$out1"
		return 1
	fi

	return 0
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

testit "smbspool_krb5_wrapper AuthInfoRequired=(sth unknown)" \
	test_smbspool_authinforequired_unknown || \
	failed=$(expr $failed + 1)

testit "smbspool print example.ps" \
	$samba_smbspool smb://$USERNAME:$PASSWORD@$SERVER_IP/print1 200 $USERNAME "Testprint" 1 "options" $SRCDIR/testdata/printing/example.ps || \
	failed=$(expr $failed + 1)

testit "vlp verify example.ps" \
	test_vlp_verify \
	|| failed=$(expr $failed + 1)

testit "smbspool print example.ps via stdin" \
	$samba_smbspool smb://$USERNAME:$PASSWORD@$SERVER_IP/print1 200 $USERNAME "Testprint" 1 "options" < $SRCDIR/testdata/printing/example.ps || \
	failed=$(expr $failed + 1)

testit "vlp verify example.ps" \
	test_vlp_verify \
	|| failed=$(expr $failed + 1)

DEVICE_URI="smb://$USERNAME:$PASSWORD@$SERVER_IP/print1"
export DEVICE_URI
testit "smbspool print DEVICE_URI example.ps" \
	$samba_smbspool 200 $USERNAME "Testprint" 1 "options" $SRCDIR/testdata/printing/example.ps || \
	failed=$(expr $failed + 1)
unset DEVICE_URI

testit "vlp verify example.ps" \
	test_vlp_verify \
	|| failed=$(expr $failed + 1)

DEVICE_URI="smb://$USERNAME:$PASSWORD@$SERVER_IP/print1"
export DEVICE_URI
testit "smbspool print DEVICE_URI example.ps via stdin" \
	$samba_smbspool 200 $USERNAME "Testprint" 1 "options" < $SRCDIR/testdata/printing/example.ps || \
	failed=$(expr $failed + 1)
unset DEVICE_URI

testit "vlp verify example.ps" \
	test_vlp_verify \
	|| failed=$(expr $failed + 1)

DEVICE_URI="smb://$USERNAME:$PASSWORD@$SERVER_IP/print1"
export DEVICE_URI
testit "smbspool print sanitized Device URI in argv0 example.ps" \
	$smbspool_argv_wrapper $samba_smbspool smb://$SERVER_IP/print1 200 $USERNAME "Testprint" 1 "options" $SRCDIR/testdata/printing/example.ps || \
	failed=$(expr $failed + 1)
unset DEVICE_URI

testit "vlp verify example.ps" \
	test_vlp_verify \
	|| failed=$(expr $failed + 1)

DEVICE_URI="smb://$USERNAME:$PASSWORD@$SERVER_IP/print1"
export DEVICE_URI
testit "smbspool print sanitized Device URI in argv0 example.ps via stdin" \
	$smbspool_argv_wrapper $samba_smbspool smb://$SERVER_IP/print1 200 $USERNAME "Testprint" 1 "options" < $SRCDIR/testdata/printing/example.ps || \
	failed=$(expr $failed + 1)
unset DEVICE_URI

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

testit "delete on close" \
	test_delete_on_close \
	|| failed=$(expr $failed + 1)

exit $failed
