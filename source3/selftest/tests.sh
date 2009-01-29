#!/bin/sh
# This script generates a list of testsuites that should be run as part of 
# the Samba 3 test suite.

# The output of this script is parsed by selftest.pl, which then decides 
# which of the tests to actually run. It will, for example, skip all tests 
# listed in selftest/skip or only run a subset during "make quicktest".

# The idea is that this script outputs all of the tests of Samba 3, not 
# just those that are known to pass, and list those that should be skipped 
# or are known to fail in selftest/skip or selftest/samba4-knownfail. This makes it 
# very easy to see what functionality is still missing in Samba 3 and makes 
# it possible to run the testsuite against other servers, such as Samba 4 or 
# Windows that have a different set of features.

# The syntax for a testsuite is "-- TEST --" on a single line, followed 
# by the name of the test, the environment it needs and the command to run, all 
# three separated by newlines. All other lines in the output are considered 
# comments.

if [ ! -n "$PERL" ]
then
	PERL=perl
fi

plantest() {
	name=$1
	env=$2
	shift 2
	cmdline="$*"
	echo "-- TEST --"
	if [ "$env" = "none" ]; then
		echo "samba3.$name"
	else
		echo "samba3.$name ($env)"
	fi
	echo $env
	echo $cmdline
}

normalize_testname() {
	name=$1
	shift 1
	echo $name | tr "A-Z-" "a-z."
}

BINDIR=`dirname $0`/../bin
SCRIPTDIR=`dirname $0`/../script/tests
export SCRIPTDIR

plantest "talloctort" none $VALGRIND $BINDIR/talloctort 
plantest "replacetort" none $VALGRIND $BINDIR/replacetort
plantest "tdbtorture" none $VALGRIND $BINDIR/tdbtorture
plantest "smbconftort" none $VALGRIND $BINDIR/smbconftort $CONFIGURATION

tests="FDPASS LOCK1 LOCK2 LOCK3 LOCK4 LOCK5 LOCK6 LOCK7"
tests="$tests UNLINK BROWSE ATTR TRANS2 TORTURE "
tests="$tests OPLOCK1 OPLOCK2 OPLOCK3"
tests="$tests DIR DIR1 TCON TCONDEV RW1 RW2 RW3"
tests="$tests OPEN XCOPY RENAME DELETE PROPERTIES W2K"
tests="$tests TCON2 IOCTL CHKPATH FDSESS LOCAL-SUBSTITUTE"

for t in $tests; do
	name=`normalize_testname $t`
    plantest "$name" dc $VALGRIND $BINDIR/smbtorture //\$SERVER/tmp -U\$USERNAME%\$PASSWORD $t
done

plantest "blackbox.smbclient" dc BINDIR="$BINDIR" script/tests/test_smbclient_s3.sh \$SERVER \$SERVER_IP \$USERNAME \$PASSWORD
plantest "blackbox.wbinfo" dc BINDIR="$BINDIR" script/tests/test_wbinfo_s3.sh \$DOMAIN \$SERVER \$USERNAME \$PASSWORD
plantest "blackbox.net" dc BINDIR="$BINDIR" SCRIPTDIR="$SCRIPTDIR" script/tests/test_net_s3.sh
