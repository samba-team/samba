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
rpcclient="$BINDIR/rpcclient"

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

test_empty_queue()
{
	# Try several times until the bgqd daemon updates the print queue status
	tries="3"
	for i in $(seq 1 $tries); do
		echo "Try $i"
		JOBS=$($rpcclient ncacn_np:$SERVER_IP \
			-U $DOMAIN/$USERNAME%$PASSWORD \
			-c "enumjobs print_var_exp 2")
		if [ $? -ne 0 ]; then
			return 1
		fi
		if [[ -z $JOBS ]]; then
			return 0
		fi
		if [[ $i -gt $tries ]]; then
			echo "Print queue not empty after $tries seconds:"
			echo $JOBS
			echo "Queue must be empty before leaving this test or" \
			     "following ones may fail."
			return 1
		fi
		sleep 1
	done
	return 0
}

testit "Test variable expansion for '%U', '%u' and '%D'" \
	test_var_expansion ||
	failed=$(expr $failed + 1)

testit "Test queue is empty" \
	test_empty_queue ||
	failed=$(expr $failed + 1)

exit $failed
