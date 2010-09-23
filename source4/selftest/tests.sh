#!/bin/sh
# This script generates a list of testsuites that should be run as part of 
# the Samba 4 test suite.

# The output of this script is parsed by selftest.pl, which then decides 
# which of the tests to actually run. It will, for example, skip all tests 
# listed in selftest/skip or only run a subset during "make quicktest".

# The idea is that this script outputs all of the tests of Samba 4, not 
# just those that are known to pass, and list those that should be skipped 
# or are known to fail in selftest/skip or selftest/knownfail. This makes it 
# very easy to see what functionality is still missing in Samba 4 and makes 
# it possible to run the testsuite against other servers, such as Samba 3 or 
# Windows that have a different set of features.

# The syntax for a testsuite is "-- TEST --" on a single line, followed 
# by the name of the test, the environment it needs and the command to run, all 
# three separated by newlines. All other lines in the output are considered 
# comments.

if [ ! -n "$PERL" ]
then
	PERL=perl
fi

if [ ! -n "$PYTHON" ]
then
	PYTHON=python
fi

plantestsuite() {
	name=$1
	env=$2
	shift 2
	cmdline="$*"
	echo "-- TEST --"
	echo $name
	echo $env
	echo "$cmdline 2>&1 | ../selftest/filter-subunit --prefix=\"$name.\""
}

plantestsuite_loadlist() {
	name=$1
	env=$2
	shift 2
	cmdline="$*"
	echo "-- TEST-LOADLIST --"
	if [ "$env" = "none" ]; then
		fullname="$name"
	else
		fullname="$name ($env)"
	fi
	echo $fullname
	echo $env
	echo "$cmdline \$LOADLIST 2>&1 | ../selftest/filter-subunit --prefix=\"$fullname.\""
}

plantestsuite_idlist() {
	name=$1
	env=$2
	shift 2
	cmdline="$*"
	echo "-- TEST-IDLIST --"
	echo $name
	echo $env
	echo $cmdline
}

skiptestsuite() {
	name=$1
	reason=$2
	shift 2
	# FIXME: Report this using subunit, but re-adjust the testsuite count somehow
	echo "skipping $name ($reason)"
}

normalize_testname() {
	name=$1
	shift 1
	echo $name | tr "A-Z- " "a-z._"
}

planperltestsuite() {
	name=$1
	shift 1
	cmdline="$*"
	if $PERL -e 'eval require Test::More;' > /dev/null 2>&1; then
		plantestsuite "$name" "none" $PERL $cmdline "|" $TAP2SUBUNIT 
	else
		skiptestsuite "$name" "Test::More not available"
	fi
}

planpythontestsuite() {
	env=$1
	module=$2
	shift 2
	plantestsuite_idlist "$module" "$env" PYTHONPATH=$PYTHONPATH:$samba4srcdir/../lib/subunit/python:$samba4srcdir/../lib/testtools $PYTHON -m subunit.run $module
}

plansmbtorturetestsuite() {
	name=$1
	env=$2
	shift 2
	other_args="$*"
	modname="samba4.`normalize_testname $name`"
	cmdline="$VALGRIND $smb4torture $other_args $name"
	plantestsuite_loadlist "$modname" "$env" $cmdline
}

samba4srcdir="`dirname $0`/.."
if [ -z "$BUILDDIR" ]; then
	BUILDDIR="$samba4srcdir"
fi
samba4bindir="$BUILDDIR/bin"
smb4torture="$samba4bindir/smbtorture${EXEEXT}"
if which tap2subunit 2>/dev/null; then
	TAP2SUBUNIT=tap2subunit
else
	TAP2SUBUNIT="PYTHONPATH=$samba4srcdir/../lib/subunit/python:$samba4srcdir/../lib/testtools $PYTHON $samba4srcdir/../lib/subunit/filters/tap2subunit"
fi
$smb4torture -V

bbdir=../testprogs/blackbox

CONFIGURATION="--configfile=\$SMB_CONF_PATH"

rm -rf $SELFTEST_PREFIX/s4client
mkdir -p $SELFTEST_PREFIX/s4client

TORTURE_OPTIONS=""
TORTURE_OPTIONS="$TORTURE_OPTIONS $CONFIGURATION"
TORTURE_OPTIONS="$TORTURE_OPTIONS --maximum-runtime=$SELFTEST_MAXTIME"
TORTURE_OPTIONS="$TORTURE_OPTIONS --target=$SELFTEST_TARGET"
TORTURE_OPTIONS="$TORTURE_OPTIONS --basedir=$SELFTEST_PREFIX/s4client"
if [ -z "$SELFTEST_VERBOSE" ]; then
	TORTURE_OPTIONS="$TORTURE_OPTIONS --option=torture:progress=no"
fi
TORTURE_OPTIONS="$TORTURE_OPTIONS --format=subunit"
if [ -n "$SELFTEST_QUICK" ]; then
	TORTURE_OPTIONS="$TORTURE_OPTIONS --option=torture:quick=yes"
fi
smb4torture="$smb4torture $TORTURE_OPTIONS"

echo "OPTIONS $TORTURE_OPTIONS"

# Simple tests for LDAP and CLDAP

for options in "" "--option=socket:testnonblock=true" "-U\$USERNAME%\$PASSWORD --option=socket:testnonblock=true" "-U\$USERNAME%\$PASSWORD" "-U\$USERNAME%\$PASSWORD -k yes" "-U\$USERNAME%\$PASSWORD -k no" "-U\$USERNAME%\$PASSWORD -k no --sign" "-U\$USERNAME%\$PASSWORD -k no --encrypt" "-U\$USERNAME%\$PASSWORD -k yes --encrypt" "-U\$USERNAME%\$PASSWORD -k yes --sign"; do
	plantestsuite "samba4.ldb.ldap with options $options (dc)" dc $bbdir/test_ldb.sh ldap \$SERVER $options
done
# see if we support ldaps
[ -n "$CONFIG_H" ] || {
	CONFIG_H="$samba4bindir/default/source4/include/config.h"
}
if grep ENABLE_GNUTLS.1 $CONFIG_H > /dev/null; then
	for options in "" "-U\$USERNAME%\$PASSWORD"; do
		plantestsuite "samba4.ldb.ldaps with options $options (dc)" dc $bbdir/test_ldb.sh ldaps \$SERVER_IP $options
	done
fi
for options in "" "-U\$USERNAME%\$PASSWORD"; do
	plantestsuite "samba4.ldb.ldapi with options $options (dc:local)" dc:local $bbdir/test_ldb.sh ldapi \$PREFIX_ABS/dc/private/ldapi $options
done
for t in `$smb4torture --list | grep "^LDAP-"`
do
	plansmbtorturetestsuite "$t" dc "-U\$USERNAME%\$PASSWORD" //\$SERVER_IP/_none_
done

LDBDIR=$samba4srcdir/lib/ldb
export LDBDIR
# Don't run LDB tests when using system ldb, as we won't have ldbtest installed
if [ -f $samba4bindir/ldbtest ]; then
	plantestsuite "ldbbase" none TEST_DATA_PREFIX=\$PREFIX $LDBDIR/tests/test-tdb.sh
else
	skiptestsuite "ldbbase" "Using system LDB, ldbtest not available"
fi

# Tests for RPC

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests="RPC-SCHANNEL RPC-JOIN RPC-LSA RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND RPC-NETLOGON RPC-HANDLES RPC-SAMSYNC RPC-SAMBA3-SESSIONKEY RPC-SAMBA3-GETUSERNAME RPC-SAMBA3-LSA RPC-SAMBA3-BIND RPC-SAMBA3-NETLOGON RPC-ASYNCBIND RPC-LSALOOKUP RPC-LSA-GETUSER RPC-SCHANNEL2 RPC-AUTHCONTEXT"
ncalrpc_tests="RPC-SCHANNEL RPC-JOIN RPC-LSA RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND RPC-NETLOGON RPC-DRSUAPI RPC-ASYNCBIND RPC-LSALOOKUP RPC-LSA-GETUSER RPC-SCHANNEL2 RPC-AUTHCONTEXT"
drs_rpc_tests=`$smb4torture --list | grep '^DRS-RPC'`
ncacn_ip_tcp_tests="RPC-SCHANNEL RPC-JOIN RPC-LSA RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND RPC-NETLOGON RPC-HANDLES RPC-ASYNCBIND RPC-LSALOOKUP RPC-LSA-GETUSER RPC-SCHANNEL2 RPC-AUTHCONTEXT RPC-OBJECTUUID $drs_rpc_tests"
slow_ncacn_np_tests="RPC-SAMLOGON RPC-SAMR RPC-SAMR-USERS RPC-SAMR-LARGE-DC RPC-SAMR-USERS-PRIVILEGES RPC-SAMR-PASSWORDS RPC-SAMR-PASSWORDS-PWDLASTSET"
slow_ncalrpc_tests="RPC-SAMR RPC-SAMR-PASSWORDS"
slow_ncacn_ip_tcp_tests="RPC-SAMR RPC-SAMR-PASSWORDS RPC-CRACKNAMES"

all_tests="$ncalrpc_tests $ncacn_np_tests $ncacn_ip_tcp_tests $slow_ncalrpc_tests $slow_ncacn_np_tests $slow_ncacn_ip_tcp_tests RPC-LSA-SECRETS RPC-SAMBA3-SHARESEC RPC-COUNTCALLS"

# Make sure all tests get run
rpc_tests=`$smb4torture --list | grep '^RPC-'`
rpc_tests_list="${rpc_tests}"
for t in $rpc_tests_list
do
	echo $all_tests | grep "$t"  > /dev/null
	if [ $? -ne 0 ]
	then
		auto_rpc_tests="$auto_rpc_tests $t"
	fi
done

for bindoptions in seal,padcheck $VALIDATE bigendian; do
	for transport in ncalrpc ncacn_np ncacn_ip_tcp; do
		env="dc"
		case $transport in
			 ncalrpc) tests=$ncalrpc_tests;env="dc:local" ;;
			 ncacn_np) tests=$ncacn_np_tests ;;
			 ncacn_ip_tcp) tests=$ncacn_ip_tcp_tests ;;
		esac
		for t in $tests; do
			plantestsuite_loadlist "samba4.`normalize_testname $t` on $transport with $bindoptions" $env $VALGRIND $smb4torture $transport:"\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
		done
		plantestsuite_loadlist "samba4.rpc.samba3.sharesec on $transport with $bindoptions" $env $VALGRIND $smb4torture $transport:"\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN --option=torture:share=tmp RPC-SAMBA3-SHARESEC "$*"
	done
done

for bindoptions in "" $VALIDATE bigendian; do
	for t in $auto_rpc_tests; do
		plantestsuite_loadlist "samba4.`normalize_testname $t` with $bindoptions" dc $VALGRIND $smb4torture "\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
	done
done

t="RPC-COUNTCALLS"
plantestsuite_loadlist "samba4.`normalize_testname $t`" dc:local $VALGRIND $smb4torture "\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"

for bindoptions in connect $VALIDATE ; do
	for transport in ncalrpc ncacn_np ncacn_ip_tcp; do
		env="dc"
		case $transport in
			ncalrpc) tests=$slow_ncalrpc_tests; env="dc:local" ;;
			ncacn_np) tests=$slow_ncacn_np_tests ;;
			ncacn_ip_tcp) tests=$slow_ncacn_ip_tcp_tests ;;
		esac
		for t in $tests; do
			plantestsuite_loadlist "samba4.`normalize_testname $t` on $transport with $bindoptions" $env $VALGRIND $smb4torture $transport:"\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
		done
	done
done
# Tests for the DFS referral calls implementation

dfsc=`$smb4torture --list | grep "^DFS-" | xargs`

for t in $dfsc; do
	plansmbtorturetestsuite "$t" dc $ADDARGS //\$SERVER/ipc$ -U"\$USERNAME"%"\$PASSWORD"
done

# Tests for the NET API (NET-API-BECOME-DC tested below against all the roles)

net=`$smb4torture --list | grep "^NET-" | grep -v NET-API-BECOME-DC`

for t in $net; do
	plansmbtorturetestsuite "$t" dc "\$SERVER[$VALIDATE]" -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" "$*"
done

# Tests for session keys and encryption of RPC pipes
# FIXME: Integrate these into a single smbtorture test

bindoptions=""
transport="ncacn_np"
for ntlmoptions in \
    "-k no --option=usespnego=yes" \
    "-k no --option=usespnego=yes --option=ntlmssp_client:128bit=no" \
    "-k no --option=usespnego=yes --option=ntlmssp_client:56bit=yes" \
    "-k no --option=usespnego=yes --option=ntlmssp_client:56bit=no" \
    "-k no --option=usespnego=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=yes" \
    "-k no --option=usespnego=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=no" \
    "-k no --option=usespnego=yes --option=clientntlmv2auth=yes" \
    "-k no --option=usespnego=yes --option=clientntlmv2auth=yes --option=ntlmssp_client:128bit=no" \
    "-k no --option=usespnego=yes --option=clientntlmv2auth=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=yes" \
    "-k no --option=usespnego=no --option=clientntlmv2auth=yes" \
    "-k no --option=gensec:spnego=no --option=clientntlmv2auth=yes" \
    "-k no --option=usespnego=no"; do
    name="rpc.lsa.secrets on $transport with $bindoptions with $ntlmoptions"
	plantestsuite_loadlist "samba4.$name" dc $smb4torture $transport:"\$SERVER[$bindoptions]"  $ntlmoptions -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN --option=gensec:target_hostname=\$NETBIOSNAME RPC-LSA-SECRETS "$*"
done

transports="ncacn_np ncacn_ip_tcp"

#Kerberos varies between functional levels, so it is important to check this on all of them
for env in dc fl2000dc fl2003dc fl2008r2dc; do
	for transport in $transports; do
		plantestsuite_loadlist "samba4.rpc.lsa.secrets on $transport with $bindoptions with Kerberos" $env $smb4torture $transport:"\$SERVER[$bindoptions]" -k yes -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN "--option=gensec:target_hostname=\$NETBIOSNAME" RPC-LSA-SECRETS "$*"
		plantestsuite_loadlist "samba4.rpc.lsa.secrets on $transport with $bindoptions with Kerberos - use target principal" $env $smb4torture $transport:"\$SERVER[$bindoptions]" -k yes -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN "--option=clientusespnegoprincipal=yes" "--option=gensec:target_hostname=\$NETBIOSNAME" RPC-LSA-SECRETS "$*"
		plantestsuite_loadlist "samba4.rpc.lsa.secrets on $transport with Kerberos - use Samba3 style login" $env $smb4torture $transport:"\$SERVER" -k yes -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" "--option=gensec:fake_gssapi_krb5=yes" "--option=gensec:gssapi_krb5=no" "--option=gensec:target_hostname=\$NETBIOSNAME" "RPC-LSA-SECRETS-none*" "$*"
		plantestsuite_loadlist "samba4.rpc.lsa.secrets on $transport with Kerberos - use Samba3 style login, use target principal" $env $smb4torture $transport:"\$SERVER" -k yes -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" "--option=clientusespnegoprincipal=yes" "--option=gensec:fake_gssapi_krb5=yes" "--option=gensec:gssapi_krb5=no" "--option=gensec:target_hostname=\$NETBIOSNAME" "RPC-LSA-SECRETS-none*" "$*"
		plansmbtorturetestsuite NET-API-BECOME-DC $env "\$SERVER[$VALIDATE]" -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" "$*"
		plantestsuite_loadlist "samba4.rpc.echo on $transport with $bindoptions and $echooptions" $env $smb4torture $transport:"\$SERVER[$bindoptions]" $ntlmoptions -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" RPC-ECHO "$*"

		# Echo tests test bulk Kerberos encryption of DCE/RPC
		for bindoptions in connect spnego spnego,sign spnego,seal $VALIDATE padcheck bigendian bigendian,seal; do
			echooptions="--option=socket:testnonblock=True --option=torture:quick=yes -k yes"
			plantestsuite_loadlist "samba4.rpc.echo on $transport with $bindoptions and $echooptions" $env $smb4torture $transport:"\$SERVER[$bindoptions]" $echooptions -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" RPC-ECHO "$*"
		done
	done
done

for transport in $transports; do
	for bindoptions in sign seal; do
	for ntlmoptions in \
        "--option=ntlmssp_client:ntlm2=yes --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=no --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=yes --option=ntlmssp_client:128bit=no --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=no --option=ntlmssp_client:128bit=no --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=yes --option=ntlmssp_client:keyexchange=no --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=no --option=ntlmssp_client:keyexchange=no  --option=torture:quick=yes" \
        "--option=clientntlmv2auth=yes --option=ntlmssp_client:keyexchange=no  --option=torture:quick=yes" \
        "--option=clientntlmv2auth=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:keyexchange=yes --option=torture:quick=yes" \
        "--option=clientntlmv2auth=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:keyexchange=no --option=torture:quick=yes" \
    ; do
			env="dc"
			if test x"$transport" = x"ncalrpc"; then
				env="dc:local"
			fi
			plantestsuite_loadlist "samba4.rpc.echo on $transport with $bindoptions and $ntlmoptions" $env $smb4torture $transport:"\$SERVER[$bindoptions]" $ntlmoptions -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN RPC-ECHO "$*"
		done
	done
done

plantestsuite_loadlist "samba4.rpc.echo on ncacn_np over smb2" dc $smb4torture ncacn_np:"\$SERVER[smb2]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN RPC-ECHO "$*"

plantestsuite_loadlist "samba4.ntp.signd" dc:local $smb4torture ncacn_np:"\$SERVER" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN NTP-SIGND "$*"

# Tests against the NTVFS POSIX backend
NTVFSARGS=""
NTVFSARGS="${NTVFSARGS} --option=torture:sharedelay=10000"
NTVFSARGS="${NTVFSARGS} --option=torture:oplocktimeout=3"
NTVFSARGS="${NTVFSARGS} --option=torture:writetimeupdatedelay=50000"

smb2=`$smb4torture --list | grep "^SMB2-" | xargs`
#The QFILEINFO-IPC test needs to be on ipc$
raw=`$smb4torture --list | grep "^RAW-" | grep -v "RAW-QFILEINFO-IPC"| xargs`
base=`$smb4torture --list | grep "^BASE-" | xargs`

for t in $base $raw $smb2; do
	plansmbtorturetestsuite "$t" dc $ADDARGS //\$SERVER/tmp -U"\$USERNAME"%"\$PASSWORD" $NTVFSARGS
done

plansmbtorturetestsuite "RAW-QFILEINFO-IPC" dc $ADDARGS //\$SERVER/ipc$ -U"\$USERNAME"%"\$PASSWORD"

rap=`$smb4torture --list | grep "^RAP-" | xargs`
for t in $rap; do
	plansmbtorturetestsuite "$t" dc $ADDARGS //\$SERVER/IPC\\\$ -U"\$USERNAME"%"\$PASSWORD"
done

# Tests against the NTVFS CIFS backend
for t in $base $raw; do
    plantestsuite_loadlist "samba4.ntvfs.cifs.`normalize_testname $t`" dc $VALGRIND $smb4torture //\$NETBIOSNAME/cifs -U"\$USERNAME"%"\$PASSWORD" $NTVFSARGS $t
done

# Local tests

for t in `$smb4torture --list | grep "^LOCAL-" | xargs`; do
	plansmbtorturetestsuite "$t" none ncalrpc: "$*"
done

tdbtorture4="$samba4bindir/tdbtorture${EXEEXT}"
if test -f $tdbtorture4
then
	plantestsuite "tdb.stress" none $VALGRIND $tdbtorture4
else
	skiptestsuite "tdb.stress" "Using system TDB, tdbtorture not available"
fi

plansmbtorturetestsuite "DRS-UNIT" none ncalrpc: "$*"

# Pidl tests
for f in $samba4srcdir/../pidl/tests/*.pl; do
	planperltestsuite "pidl.`basename $f .pl`" $f
done
planperltestsuite "selftest.samba4" $samba4srcdir/../selftest/test_samba4.pl

# Blackbox Tests:
# tests that interact directly with the command-line tools rather than using 
# the API. These mainly test that the various command-line options of commands 
# work correctly.

planpythontestsuite none samba.tests.blackbox.ndrdump
plantestsuite "samba4.blackbox.net (dc:local)" dc:local $samba4srcdir/utils/tests/test_net.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN"
plantestsuite "samba4.blackbox.pkinit (dc:local)" dc:local $bbdir/test_pkinit.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$REALM" "\$DOMAIN" "$PREFIX" aes256-cts-hmac-sha1-96 $CONFIGURATION 
plantestsuite "samba4.blackbox.kinit (dc:local)" dc:local $bbdir/test_kinit.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$REALM" "\$DOMAIN" "$PREFIX" aes256-cts-hmac-sha1-96 $CONFIGURATION
plantestsuite "samba4.blackbox.kinit (fl2000dc:local)" fl2000dc:local $bbdir/test_kinit.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$REALM" "\$DOMAIN" "$PREFIX" arcfour-hmac-md5 $CONFIGURATION
plantestsuite "samba4.blackbox.kinit (fl2008r2dc:local)" fl2008r2dc:local $bbdir/test_kinit.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$REALM" "\$DOMAIN" "$PREFIX" aes256-cts-hmac-sha1-96 $CONFIGURATION
plantestsuite "samba4.blackbox.ktpass (dc)" dc $bbdir/test_ktpass.sh $PREFIX
plantestsuite "samba4.blackbox.passwords (dc:local)" dc:local $bbdir/test_passwords.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$REALM" "\$DOMAIN" "$PREFIX"
plantestsuite "samba4.blackbox.export.keytab (dc:local)" dc:local $bbdir/test_export_keytab.sh "\$SERVER" "\$USERNAME" "\$REALM" "\$DOMAIN" "$PREFIX"
plantestsuite "samba4.blackbox.cifsdd (dc)" dc $samba4srcdir/client/tests/test_cifsdd.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" 
plantestsuite "samba4.blackbox.nmblookup (dc)" dc $samba4srcdir/utils/tests/test_nmblookup.sh "\$NETBIOSNAME" "\$NETBIOSALIAS" "\$SERVER" "\$SERVER_IP" 
plantestsuite "samba4.blackbox.nmblookup (member)" member $samba4srcdir/utils/tests/test_nmblookup.sh "\$NETBIOSNAME" "\$NETBIOSALIAS" "\$SERVER" "\$SERVER_IP"
plantestsuite "samba4.blackbox.locktest (dc)" dc $samba4srcdir/torture/tests/test_locktest.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$PREFIX"
plantestsuite "samba4.blackbox.masktest (masktest)" dc $samba4srcdir/torture/tests/test_masktest.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$PREFIX"
plantestsuite "samba4.blackbox.gentest (dc)" dc $samba4srcdir/torture/tests/test_gentest.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$PREFIX"
plantestsuite "samba4.blackbox.wbinfo (dc:local)" dc:local $samba4srcdir/../nsswitch/tests/test_wbinfo.sh "\$DOMAIN" "\$USERNAME" "\$PASSWORD" "dc"
plantestsuite "samba4.blackbox.wbinfo (member:local)" member:local $samba4srcdir/../nsswitch/tests/test_wbinfo.sh "\$DOMAIN" "\$DC_USERNAME" "\$DC_PASSWORD" "member"
plantestsuite "samba4.blackbox.chgdcpass (dc)" dc $bbdir/test_chgdcpass.sh "\$SERVER" "LOCALDC\\\$" "\$REALM" "\$DOMAIN" "$PREFIX" aes256-cts-hmac-sha1-96 $SELFTEST_PREFIX/dc

# Tests using the "Simple" NTVFS backend
for t in "BASE-RW1"; do
	plantestsuite_loadlist "samba4.ntvfs.simple.`normalize_testname $t`" dc $VALGRIND $smb4torture $ADDARGS //\$SERVER/simple -U"\$USERNAME"%"\$PASSWORD" $t
done

# Domain Member Tests
plantestsuite_loadlist "samba4.rpc.echo against member server with local creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" RPC-ECHO "$*"
plantestsuite_loadlist "samba4.rpc.echo against member server with domain creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD" RPC-ECHO "$*"
plantestsuite_loadlist "samba4.rpc.samr against member server with local creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR" "$*"
plantestsuite_loadlist "samba4.rpc.samr.users against member server with local creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR-USERS" "$*"
plantestsuite_loadlist "samba4.rpc.samr.passwords against member server with local creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR-PASSWORDS" "$*"
plantestsuite "samba4.blackbox.smbclient against member server with local creds" member $samba4srcdir/client/tests/test_smbclient.sh "\$NETBIOSNAME" "\$USERNAME" "\$PASSWORD" "\$NETBIOSNAME" "$PREFIX" 

# RPC Proxy
plantestsuite_loadlist "samba4.rpc.echo against rpc proxy with domain creds" rpc_proxy $VALGRIND $smb4torture ncacn_ip_tcp:"\$NETBIOSNAME" -U"\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD" RPC-ECHO "$*"

# Tests SMB signing
for mech in \
	"-k no" \
	"-k no --option=usespnego=no" \
	"-k no --option=gensec:spengo=no" \
	"-k yes" \
	"-k yes --option=gensec:fake_gssapi_krb5=yes --option=gensec:gssapi_krb5=no"; do
   for signing in \
	"--signing=on" \
	"--signing=required"; do

	signoptions="$mech $signing"
	name="smb.signing on with $signoptions"
	plantestsuite_loadlist "samba4.$name" dc $VALGRIND $smb4torture //"\$NETBIOSNAME"/tmp $signoptions -U"\$USERNAME"%"\$PASSWORD" BASE-XCOPY "$*"
   done
done

for mech in \
	"-k no" \
	"-k no --option=usespnego=no" \
	"-k no --option=gensec:spengo=no" \
	"-k yes" \
	"-k yes --option=gensec:fake_gssapi_krb5=yes --option=gensec:gssapi_krb5=no"; do
	signoptions="$mech --signing=off"
	name="smb.signing on with $signoptions"
	plantestsuite_loadlist "samba4.$name domain-creds" member $VALGRIND $smb4torture //"\$NETBIOSNAME"/tmp $signoptions -U"\$DC_USERNAME"%"\$DC_PASSWORD" BASE-XCOPY "$*"
done
for mech in \
	"-k no" \
	"-k no --option=usespnego=no" \
	"-k no --option=gensec:spengo=no"; do
	signoptions="$mech --signing=off"
	name="smb.signing on with $signoptions"
	plantestsuite_loadlist "samba4.$name local-creds" member $VALGRIND $smb4torture //"\$NETBIOSNAME"/tmp $signoptions -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" BASE-XCOPY "$*"
done
plantestsuite_loadlist "samba4.smb.signing --signing=yes anon" dc $VALGRIND $smb4torture //"\$NETBIOSNAME"/tmp -k no --signing=yes -U% BASE-XCOPY "$*"
plantestsuite_loadlist "samba4.smb.signing --signing=required anon" dc $VALGRIND $smb4torture //"\$NETBIOSNAME"/tmp -k no --signing=required -U% BASE-XCOPY "$*"
plantestsuite_loadlist "samba4.smb.signing --signing=no anon" member $VALGRIND $smb4torture //"\$NETBIOSNAME"/tmp -k no --signing=no -U% BASE-XCOPY "$*"

NBT_TESTS=`$smb4torture --list | grep "^NBT-" | xargs`
for t in $NBT_TESTS; do
	plansmbtorturetestsuite "$t" dc //\$SERVER/_none_ -U\$USERNAME%\$PASSWORD 
done

WB_OPTS="--option=\"torture:strict mode=no\""
WB_OPTS="${WB_OPTS} --option=\"torture:timelimit=1\""
WB_OPTS="${WB_OPTS} --option=\"torture:winbindd_separator=/\""
WB_OPTS="${WB_OPTS} --option=\"torture:winbindd_netbios_name=\$SERVER\""
WB_OPTS="${WB_OPTS} --option=\"torture:winbindd_netbios_domain=\$DOMAIN\""

WINBIND_STRUCT_TESTS=`$smb4torture --list | grep "^WINBIND-STRUCT" | xargs`
WINBIND_NDR_TESTS=`$smb4torture --list | grep "^WINBIND-NDR" | xargs`
for env in dc member; do
	for t in $WINBIND_STRUCT_TESTS; do
		plansmbtorturetestsuite $t $env $WB_OPTS //_none_/_none_
	done

	for t in $WINBIND_NDR_TESTS; do
		plansmbtorturetestsuite $t $env $WB_OPTS //_none_/_none_
	done
done

nsstest4="$samba4bindir/nsstest${EXEEXT}"
if test -f $nsstest4
then
	plantestsuite "samba4.nss.test using winbind (member)" member $VALGRIND $nsstest4 $samba4bindir/shared/libnss_winbind.so
fi

SUBUNITRUN="$VALGRIND $PYTHON $samba4srcdir/scripting/bin/subunitrun"
plantestsuite "ldb.python" none PYTHONPATH="$PYTHONPATH:$samba4srcdir/lib/ldb/tests/python/" $PYTHON $samba4srcdir/lib/ldb/tests/python/api.py
plantestsuite "samba4.credentials.python" none PYTHONPATH="$PYTHONPATH:$samba4srcdir/auth/credentials/tests" $SUBUNITRUN bindings
planpythontestsuite none samba.tests.gensec
planpythontestsuite none samba.tests.registry
plantestsuite "tdb.python" none PYTHONPATH="$PYTHONPATH:../lib/tdb/python/tests" $SUBUNITRUN simple
planpythontestsuite none samba.tests.auth
planpythontestsuite none samba.tests.security
planpythontestsuite none samba.tests.dcerpc.misc
planpythontestsuite none samba.tests.param
planpythontestsuite none samba.tests.upgrade
planpythontestsuite none samba.tests.core
planpythontestsuite none samba.tests.provision
planpythontestsuite none samba.tests.samba3
planpythontestsuite dc:local samba.tests.dcerpc.sam
planpythontestsuite dc:local samba.tests.dsdb
planpythontestsuite none samba.tests.netcmd
planpythontestsuite dc:local samba.tests.dcerpc.bare
planpythontestsuite dc:local samba.tests.dcerpc.unix
planpythontestsuite none samba.tests.dcerpc.rpc_talloc
planpythontestsuite none samba.tests.samdb
planpythontestsuite none samba.tests.shares
planpythontestsuite none samba.tests.messaging
planpythontestsuite none samba.tests.samba3sam
planpythontestsuite none subunit
planpythontestsuite dc:local samba.tests.dcerpc.rpcecho
plantestsuite_idlist "samba.tests.dcerpc.registry" dc:local $SUBUNITRUN -U\$USERNAME%\$PASSWORD samba.tests.dcerpc.registry
plantestsuite "samba4.ldap.python (dc)" dc PYTHONPATH="$PYTHONPATH:../lib/subunit/python:../lib/testtools" $PYTHON $samba4srcdir/dsdb/tests/python/ldap.py \$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
plantestsuite "samba4.schemaInfo.python (dc)" dc PYTHONPATH="$PYTHONPATH:$samba4srcdir/dsdb/tests/python/" $SUBUNITRUN dsdb_schema_info -U"\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD"
plantestsuite "samba4.urgent_replication.python (dc)" dc PYTHONPATH="$PYTHONPATH:../lib/subunit/python:../lib/testtools" $PYTHON $samba4srcdir/dsdb/tests/python/urgent_replication.py \$PREFIX_ABS/dc/private/sam.ldb
for env in "dc" "fl2000dc" "fl2003dc" "fl2008r2dc"; do
	plantestsuite "samba4.ldap_schema.python ($env)" $env PYTHONPATH="$PYTHONPATH:../lib/subunit/python:../lib/testtools" $PYTHON $samba4srcdir/dsdb/tests/python/ldap_schema.py \$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
	plantestsuite "samba4.ldap.possibleInferiors.python ($env)" $env $PYTHON $samba4srcdir/dsdb/samdb/ldb_modules/tests/possibleinferiors.py ldap://\$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
	plantestsuite "samba4.ldap.secdesc.python ($env)" $env PYTHONPATH="$PYTHONPATH:../lib/subunit/python:../lib/testtools" $PYTHON $samba4srcdir/dsdb/tests/python/sec_descriptor.py \$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
	plantestsuite "samba4.ldap.acl.python ($env)" $env PYTHONPATH="$PYTHONPATH:../lib/subunit/python:../lib/testtools" $PYTHON $samba4srcdir/dsdb/tests/python/acl.py \$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
	plantestsuite "samba4.ldap.passwords.python ($env)" $env PYTHONPATH="$PYTHONPATH:../lib/subunit/python:../lib/testtools" $PYTHON $samba4srcdir/dsdb/tests/python/passwords.py \$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
done
planpythontestsuite dc:local samba.tests.upgradeprovisionneeddc
planpythontestsuite none samba.tests.upgradeprovision
planpythontestsuite none samba.tests.xattr
planpythontestsuite none samba.tests.ntacls
plantestsuite "samba4.deletetest.python (dc)" dc PYTHONPATH="$PYTHONPATH:../lib/subunit/python:../lib/testtools" $PYTHON $samba4srcdir/dsdb/tests/python/deletetest.py \$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
plantestsuite "samba4.policy.python" none PYTHONPATH="$PYTHONPATH:lib/policy/tests/python" $SUBUNITRUN bindings
plantestsuite "samba4.blackbox.samba3dump" none $PYTHON $samba4srcdir/scripting/bin/samba3dump $samba4srcdir/../testdata/samba3
rm -rf $PREFIX/upgrade
plantestsuite "samba4.blackbox.upgrade" none $PYTHON $samba4srcdir/setup/upgrade_from_s3 --targetdir=$PREFIX/upgrade $samba4srcdir/../testdata/samba3 ../testdata/samba3/smb.conf
rm -rf $PREFIX/provision
mkdir $PREFIX/provision
plantestsuite "samba4.blackbox.provision.py" none PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_provision.sh "$PREFIX/provision"
plantestsuite "samba4.blackbox.provision-backend.py" none PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_provision-backend.sh "$PREFIX/provision"
plantestsuite "samba4.blackbox.upgradeprovision.py" none PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_upgradeprovision.sh "$PREFIX/provision"
plantestsuite "samba4.blackbox.setpassword.py" none PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_setpassword.sh "$PREFIX/provision"
plantestsuite "samba4.blackbox.newuser.py" none PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_newuser.sh "$PREFIX/provision"
plantestsuite "samba4.blackbox.group.py" none PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_group.sh "$PREFIX/provision"
plantestsuite "samba4.blackbox.spn.py (dc:local)" dc:local PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_spn.sh "$PREFIX/dc"

# DRS python tests
plantestsuite "samba4.drs_delete_object.python (vampire_dc)" vampire_dc PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" DC1=\$DC_SERVER DC2=\$VAMPIRE_DC_SERVER $SUBUNITRUN delete_object -U"\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD"
plantestsuite "samba4.drs_fsmo.python (vampire_dc)" vampire_dc PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" DC1=\$DC_SERVER DC2=\$VAMPIRE_DC_SERVER $SUBUNITRUN fsmo -U"\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD"

# This makes sure we test the rid allocation code
t="RPC-SAMR-LARGE-DC"
plantestsuite_loadlist "samba4.`normalize_testname $t.one`" vampire_dc $VALGRIND $smb4torture "\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
plantestsuite_loadlist "samba4.`normalize_testname $t.two`" vampire_dc $VALGRIND $smb4torture "\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"

# some RODC testing
plantestsuite_loadlist "samba4.rpc.echo to RODC" "rodc" $smb4torture ncacn_np:"\$SERVER" -k yes -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" RPC-ECHO "$*"
