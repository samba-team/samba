#!/bin/sh

if [ $# -lt 4 ]; then
	cat <<EOF
Usage: test_smbspool.sh SERVER SERVER_IP DOMAIN USERNAME PASSWORD
EOF
	exit 1
fi

SERVER="$1"
SERVER_IP="$2"
DOMAIN="$3"
USERNAME="$4"
PASSWORD="$5"
shift 5
ADDARGS="$@"

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh
. $incdir/common_test_fns.inc

smbclient="$BINDIR/smbclient"

test_var_expansion()
{
	logfile="${SELFTEST_TMPDIR}/${USER}_printing_var_exp.log"

	$smbclient -U $DOMAIN/$USERNAME%$PASSWORD \
		//$SERVER_IP/print_var_exp \
		-c "print $SRCDIR/testdata/printing/example.ps"
	if [ $? -ne 0 ]; then
		rm -f "$logfile"
		return 1
	fi
	cat "$logfile"

	grep "Windows user: $USERNAME" "$logfile"
	if [ $? -ne 0 ]; then
		rm -f "$logfile"
		return 1
	fi
	grep "UNIX user: $USERNAME" "$logfile"
	if [ $? -ne 0 ]; then
		rm -f "$logfile"
		return 1
	fi
	grep "Domain: $DOMAIN" "$logfile"
	if [ $? -ne 0 ]; then
		rm -f "$logfile"
		return 1
	fi

	rm -f "$logfile"
	return 0
}

testit "Test variable expansion for '%U', '%u' and '%D'" \
	test_var_expansion ||
	failed=$(expr $failed + 1)

exit $failed
