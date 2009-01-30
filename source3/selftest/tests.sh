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

TEST_FUNCTIONS_SH="INCLUDED"
testit() {
	name=$1
	shift 1
	cmdline="$*"

	plantest "`normalize_testname $testitprefix$name`" $testitenv $cmdline
	return
}

testok() {
	true
	return
}

BINDIR=`dirname $0`/../bin
export BINDIR

SCRIPTDIR=`dirname $0`/../script/tests
export SCRIPTDIR

CONFIGURATION="--configfile \$SMB_CONF_PATH"
export CONFIGURATION

CONFFILE="\$SMB_CONF_PATH"
export CONFFILE

SERVER="\$SERVER"
export SERVER

USERNAME="\$USERNAME"
export USERNAME

PASSWORD="\$PASSWORD"
export PASSWORD

(
	shift $#
	testitprefix="local_s3."
	testitenv="none"
	. $SCRIPTDIR/test_local_s3.sh
)

(
	shift $#
	testitprefix="smbtorture_s3.plain."
	testitenv="dc"
	. $SCRIPTDIR/test_smbtorture_s3.sh //\$SERVER_IP/tmp \$USERNAME \$PASSWORD ""
)

(
	shift $#
	testitprefix="smbtorture_s3.crypt."
	testitenv="dc"
	. $SCRIPTDIR/test_smbtorture_s3.sh //\$SERVER_IP/tmp \$USERNAME \$PASSWORD "-e"
)

(
	shift $#
	testitprefix="wbinfo_s3."
	testitenv="dc:local"
	. $SCRIPTDIR/test_wbinfo_s3.sh \$WORKGROUP \$SERVER \$USERNAME \$PASSWORD
)

(
	shift $#
	testitprefix="ntlm_auth_s3."
	testitenv="dc:local"
	. $SCRIPTDIR/test_ntlm_auth_s3.sh
)

# plain
plantest "blackbox.smbclient_s3.plain" dc BINDIR="$BINDIR" script/tests/test_smbclient_s3.sh \$SERVER \$SERVER_IP \$USERNAME \$PASSWORD
plantest "blackbox.smbclient_s3.plain member creds" member BINDIR="$BINDIR" script/tests/test_smbclient_s3.sh \$SERVER \$SERVER_IP \$SERVER\\\\\$USERNAME \$PASSWORD
plantest "blackbox.smbclient_s3.plain domain creds" member BINDIR="$BINDIR" script/tests/test_smbclient_s3.sh \$SERVER \$SERVER_IP \$DOMAIN\\\\\$DC_USERNAME \$DC_PASSWORD

# encrypted
plantest "blackbox.smbclient_s3.crypt" dc BINDIR="$BINDIR" script/tests/test_smbclient_s3.sh \$SERVER \$SERVER_IP \$USERNAME \$PASSWORD "-e"

# these don't work yet
#plantest "blackbox.smbclient_s3.crypt member creds" member BINDIR="$BINDIR" script/tests/test_smbclient_s3.sh \$SERVER \$SERVER_IP \$SERVER\\\\\$USERNAME \$PASSWORD "-e"
#plantest "blackbox.smbclient_s3.crypt domain creds" member BINDIR="$BINDIR" script/tests/test_smbclient_s3.sh \$SERVER \$SERVER_IP \$DOMAIN\\\\\$DC_USERNAME \$DC_PASSWORD "-e"

plantest "blackbox.net_s3" dc BINDIR="$BINDIR" SCRIPTDIR="$SCRIPTDIR" script/tests/test_net_s3.sh

