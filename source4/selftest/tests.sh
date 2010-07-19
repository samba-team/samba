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
	if [ "$env" = "none" ]; then
		echo "samba4.$name"
	else
		echo "samba4.$name ($env)"
	fi
	echo $env
	echo $cmdline
}

plantestsuite_loadlist() {
	name=$1
	env=$2
	shift 2
	cmdline="$*"
	echo "-- TEST-LOADLIST --"
	if [ "$env" = "none" ]; then
		echo "samba4.$name"
	else
		echo "samba4.$name ($env)"
	fi
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
	env=$2
	shift 2
	cmdline="$*"
	if $PERL -e 'eval require Test::More;' > /dev/null 2>&1; then
		plantestsuite "$name" "$env" $PERL $cmdline "|" $TAP2SUBUNIT 
	else
		skiptestsuite "$name" "Test::More not available"
	fi
}

plansmbtorturetestsuite() {
	name=$1
	env=$2
	shift 2
	other_args="$*"
	modname=`normalize_testname $name`
	cmdline="$VALGRIND $smb4torture $other_args $name"
	plantestsuite "$modname" "$env" $cmdline
}

samba4srcdir="`dirname $0`/.."
samba4bindir="$BUILDDIR/bin"
smb4torture="$samba4bindir/smbtorture${EXEEXT}"
if which tap2subunit 2>/dev/null; then
	TAP2SUBUNIT=tap2subunit
else
	TAP2SUBUNIT="PYTHONPATH=$samba4srcdir/../lib/subunit/python:$samba4srcdir/../lib/testtools $PYTHON $samba4srcdir/../lib/subunit/filters/tap2subunit"
fi
$smb4torture -V

bbdir=../testprogs/blackbox

prefix_abs="$SELFTEST_PREFIX/s4client"
CONFIGURATION="--configfile=\$SMB_CONF_PATH"

test -d "$prefix_abs" || mkdir "$prefix_abs"

TORTURE_OPTIONS=""
TORTURE_OPTIONS="$TORTURE_OPTIONS $CONFIGURATION"
TORTURE_OPTIONS="$TORTURE_OPTIONS --maximum-runtime=$SELFTEST_MAXTIME"
TORTURE_OPTIONS="$TORTURE_OPTIONS --target=$SELFTEST_TARGET"
TORTURE_OPTIONS="$TORTURE_OPTIONS --basedir=$prefix_abs"
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
    plantestsuite "ldb.ldap with options $options" dc $bbdir/test_ldb.sh ldap \$SERVER $options
done
# see if we support ldaps
[ -n "$CONFIG_H" ] || {
    CONFIG_H="include/config.h"
}
if grep ENABLE_GNUTLS.1 $CONFIG_H > /dev/null; then
    for options in "" "-U\$USERNAME%\$PASSWORD"; do
	plantestsuite "ldb.ldaps with options $options" dc $bbdir/test_ldb.sh ldaps \$SERVER_IP $options
    done
fi
for options in "" "-U\$USERNAME%\$PASSWORD"; do
    plantestsuite "ldb.ldapi with options $options" dc $bbdir/test_ldb.sh ldapi \$PREFIX_ABS/dc/private/ldapi $options
done
for t in `$smb4torture --list | grep "^LDAP-"`
do
	plansmbtorturetestsuite "$t" dc "-U\$USERNAME%\$PASSWORD" //\$SERVER_IP/_none_
done

# only do the ldb tests when not in quick mode - they are quite slow, and ldb
# is now pretty well tested by the rest of the quick tests anyway
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
ncacn_ip_tcp_tests="RPC-SCHANNEL RPC-JOIN RPC-LSA RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND RPC-NETLOGON RPC-HANDLES RPC-DSSYNC RPC-ASYNCBIND RPC-LSALOOKUP RPC-LSA-GETUSER RPC-SCHANNEL2 RPC-AUTHCONTEXT RPC-OBJECTUUID"
slow_ncacn_np_tests="RPC-SAMLOGON RPC-SAMR RPC-SAMR-USERS RPC-SAMR-LARGE-DC RPC-SAMR-USERS-PRIVILEGES RPC-SAMR-PASSWORDS RPC-SAMR-PASSWORDS-PWDLASTSET"
slow_ncalrpc_tests="RPC-SAMR RPC-SAMR-PASSWORDS"
slow_ncacn_ip_tcp_tests="RPC-SAMR RPC-SAMR-PASSWORDS RPC-CRACKNAMES"

all_tests="$ncalrpc_tests $ncacn_np_tests $ncacn_ip_tcp_tests $slow_ncalrpc_tests $slow_ncacn_np_tests $slow_ncacn_ip_tcp_tests RPC-LSA-SECRETS RPC-SAMBA3-SHARESEC RPC-COUNTCALLS"

# Make sure all tests get run
rpc_tests=`$smb4torture --list | grep '^RPC-'`
drs_rpc_tests=`$smb4torture --list | grep '^DRS-RPC'`
rpc_tests_list="${rpc_tests} ${drs_rpc_tests}"
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
    plantestsuite "`normalize_testname $t` on $transport with $bindoptions" $env $VALGRIND $smb4torture $transport:"\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
   done
   plantestsuite "rpc.samba3.sharesec on $transport with $bindoptions" $env $VALGRIND $smb4torture $transport:"\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN --option=torture:share=tmp RPC-SAMBA3-SHARESEC "$*"
 done
done

for bindoptions in "" $VALIDATE bigendian; do
 for t in $auto_rpc_tests; do
  plantestsuite "`normalize_testname $t` with $bindoptions" dc $VALGRIND $smb4torture "\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
 done
done

t="RPC-COUNTCALLS"
plantestsuite "`normalize_testname $t`" dc:local $VALGRIND $smb4torture "\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"

for bindoptions in connect $VALIDATE ; do
 for transport in ncalrpc ncacn_np ncacn_ip_tcp; do
     env="dc"
     case $transport in
	 ncalrpc) tests=$slow_ncalrpc_tests; env="dc:local" ;;
	 ncacn_np) tests=$slow_ncacn_np_tests ;;
	 ncacn_ip_tcp) tests=$slow_ncacn_ip_tcp_tests ;;
     esac
   for t in $tests; do
    plantestsuite "`normalize_testname $t` on $transport with $bindoptions" $env $VALGRIND $smb4torture $transport:"\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
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
    plantestsuite "$name" dc $smb4torture $transport:"\$SERVER[$bindoptions]"  $ntlmoptions -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN --option=gensec:target_hostname=\$NETBIOSNAME RPC-LSA-SECRETS "$*"
done

transports="ncacn_np ncacn_ip_tcp"

#Kerberos varies between functional levels, so it is important to check this on all of them
for env in dc fl2000dc fl2003dc fl2008r2dc; do
    for transport in $transports; do
	plantestsuite "rpc.lsa.secrets on $transport with $bindoptions with Kerberos" $env $smb4torture $transport:"\$SERVER[$bindoptions]" -k yes -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN "--option=gensec:target_hostname=\$NETBIOSNAME" RPC-LSA-SECRETS "$*"
	plantestsuite "rpc.lsa.secrets on $transport with $bindoptions with Kerberos - use target principal" $env $smb4torture $transport:"\$SERVER[$bindoptions]" -k yes -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN "--option=clientusespnegoprincipal=yes" "--option=gensec:target_hostname=\$NETBIOSNAME" RPC-LSA-SECRETS "$*"
	plantestsuite "rpc.lsa.secrets on $transport with Kerberos - use Samba3 style login" $env $smb4torture $transport:"\$SERVER" -k yes -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" "--option=gensec:fake_gssapi_krb5=yes" "--option=gensec:gssapi_krb5=no" "--option=gensec:target_hostname=\$NETBIOSNAME" "RPC-LSA-SECRETS-none*" "$*"
	plantestsuite "rpc.lsa.secrets on $transport with Kerberos - use Samba3 style login, use target principal" $env $smb4torture $transport:"\$SERVER" -k yes -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" "--option=clientusespnegoprincipal=yes" "--option=gensec:fake_gssapi_krb5=yes" "--option=gensec:gssapi_krb5=no" "--option=gensec:target_hostname=\$NETBIOSNAME" "RPC-LSA-SECRETS-none*" "$*"
	plansmbtorturetestsuite NET-API-BECOME-DC $env "\$SERVER[$VALIDATE]" -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" "$*"
	plantestsuite "rpc.echo on $transport with $bindoptions and $echooptions" $env $smb4torture $transport:"\$SERVER[$bindoptions]" $ntlmoptions -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" RPC-ECHO "$*"
	
    # Echo tests test bulk Kerberos encryption of DCE/RPC
	for bindoptions in connect spnego spnego,sign spnego,seal $VALIDATE padcheck bigendian bigendian,seal; do
	    echooptions="--option=socket:testnonblock=True --option=torture:quick=yes -k yes"
	    plantestsuite "rpc.echo on $transport with $bindoptions and $echooptions" $env $smb4torture $transport:"\$SERVER[$bindoptions]" $echooptions -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" RPC-ECHO "$*"
	done
    done
done

for transport in $transports; do
 for bindoptions in sign seal; do
  for ntlmoptions in \
        "--option=ntlmssp_client:ntlm2=yes --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=no  --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=yes --option=ntlmssp_client:128bit=no --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=no  --option=ntlmssp_client:128bit=no --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=yes --option=ntlmssp_client:keyexchange=no --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=no  --option=ntlmssp_client:keyexchange=no  --option=torture:quick=yes" \
        "--option=clientntlmv2auth=yes  --option=ntlmssp_client:keyexchange=no  --option=torture:quick=yes" \
        "--option=clientntlmv2auth=yes  --option=ntlmssp_client:128bit=no --option=ntlmssp_client:keyexchange=yes  --option=torture:quick=yes" \
        "--option=clientntlmv2auth=yes  --option=ntlmssp_client:128bit=no --option=ntlmssp_client:keyexchange=no  --option=torture:quick=yes" \
    ; do
   env="dc"
   if test x"$transport" = x"ncalrpc"; then
      env="dc:local"
   fi
   plantestsuite "rpc.echo on $transport with $bindoptions and $ntlmoptions" $env $smb4torture $transport:"\$SERVER[$bindoptions]" $ntlmoptions -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN RPC-ECHO "$*"
  done
 done
done

plantestsuite "rpc.echo on ncacn_np over smb2" dc $smb4torture ncacn_np:"\$SERVER[smb2]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN RPC-ECHO "$*"

plantestsuite "ntp.signd" dc:local $smb4torture ncacn_np:"\$SERVER" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN NTP-SIGND "$*"

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
    plantestsuite "ntvfs.cifs.`normalize_testname $t`" dc $VALGRIND $smb4torture //\$NETBIOSNAME/cifs -U"\$USERNAME"%"\$PASSWORD" $NTVFSARGS $t
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
	 planperltestsuite "pidl.`basename $f .pl`" none $f
done
planperltestsuite "selftest.samba4.pl" none $samba4srcdir/../selftest/test_samba4.pl

# Blackbox Tests:
# tests that interact directly with the command-line tools rather than using 
# the API. These mainly test that the various command-line options of commands 
# work correctly.

plantestsuite "blackbox.ndrdump" none $samba4srcdir/librpc/tests/test_ndrdump.sh
plantestsuite "blackbox.net" dc:local $samba4srcdir/utils/tests/test_net.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN"
plantestsuite "blackbox.pkinit" dc:local $bbdir/test_pkinit.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$REALM" "\$DOMAIN" "$PREFIX" aes256-cts-hmac-sha1-96 $CONFIGURATION 
plantestsuite "blackbox.kinit" dc:local $bbdir/test_kinit.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$REALM" "\$DOMAIN" "$PREFIX" aes256-cts-hmac-sha1-96 $CONFIGURATION
plantestsuite "blackbox.kinit" fl2000dc:local $bbdir/test_kinit.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$REALM" "\$DOMAIN" "$PREFIX" arcfour-hmac-md5 $CONFIGURATION
plantestsuite "blackbox.kinit" fl2008r2dc:local $bbdir/test_kinit.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$REALM" "\$DOMAIN" "$PREFIX" aes256-cts-hmac-sha1-96 $CONFIGURATION
plantestsuite "blackbox.ktpass" dc $bbdir/test_ktpass.sh $PREFIX
plantestsuite "blackbox.passwords" dc:local $bbdir/test_passwords.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$REALM" "\$DOMAIN" "$PREFIX"
plantestsuite "blackbox.export.keytab" dc:local $bbdir/test_export_keytab.sh "\$SERVER" "\$USERNAME" "\$REALM" "\$DOMAIN" "$PREFIX"
plantestsuite "blackbox.cifsdd" dc $samba4srcdir/client/tests/test_cifsdd.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" 
plantestsuite "blackbox.nmblookup" dc $samba4srcdir/utils/tests/test_nmblookup.sh "\$NETBIOSNAME" "\$NETBIOSALIAS" "\$SERVER" "\$SERVER_IP" 
plantestsuite "blackbox.nmblookup" member $samba4srcdir/utils/tests/test_nmblookup.sh "\$NETBIOSNAME" "\$NETBIOSALIAS" "\$SERVER" "\$SERVER_IP"
plantestsuite "blackbox.locktest" dc $samba4srcdir/torture/tests/test_locktest.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$PREFIX"
plantestsuite "blackbox.masktest" dc $samba4srcdir/torture/tests/test_masktest.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$PREFIX"
plantestsuite "blackbox.gentest" dc $samba4srcdir/torture/tests/test_gentest.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$PREFIX"
plantestsuite "blackbox.wbinfo" dc:local $samba4srcdir/../nsswitch/tests/test_wbinfo.sh "\$DOMAIN" "\$USERNAME" "\$PASSWORD" "dc"
plantestsuite "blackbox.wbinfo" member:local $samba4srcdir/../nsswitch/tests/test_wbinfo.sh "\$DOMAIN" "\$DC_USERNAME" "\$DC_PASSWORD" "member"
plantestsuite "blackbox.chgdcpass" dc $bbdir/test_chgdcpass.sh "\$SERVER" "LOCALDC\\\$" "\$REALM" "\$DOMAIN" "$PREFIX" aes256-cts-hmac-sha1-96 $SELFTEST_PREFIX/dc

# Tests using the "Simple" NTVFS backend

for t in "BASE-RW1"; do
    plantestsuite "ntvfs.simple.`normalize_testname $t`" dc $VALGRIND $smb4torture $ADDARGS //\$SERVER/simple -U"\$USERNAME"%"\$PASSWORD" $t
done

# Domain Member Tests

plantestsuite "rpc.echo against member server with local creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" RPC-ECHO "$*"
plantestsuite "rpc.echo against member server with domain creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD" RPC-ECHO "$*"
plantestsuite "rpc.samr against member server with local creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR" "$*"
plantestsuite "rpc.samr.users against member server with local creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR-USERS" "$*"
plantestsuite "rpc.samr.passwords against member server with local creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR-PASSWORDS" "$*"
plantestsuite "blackbox.smbclient against member server with local creds" member $samba4srcdir/client/tests/test_smbclient.sh "\$NETBIOSNAME" "\$USERNAME" "\$PASSWORD" "\$NETBIOSNAME" "$PREFIX" 

# RPC Proxy
plantestsuite "rpc.echo against rpc proxy with domain creds" rpc_proxy $VALGRIND $smb4torture ncacn_ip_tcp:"\$NETBIOSNAME" -U"\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD" RPC-ECHO "$*"

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
	plantestsuite "$name" dc $VALGRIND $smb4torture //"\$NETBIOSNAME"/tmp $signoptions -U"\$USERNAME"%"\$PASSWORD" BASE-XCOPY "$*"
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
	plantestsuite "$name domain-creds" member $VALGRIND $smb4torture //"\$NETBIOSNAME"/tmp $signoptions -U"\$DC_USERNAME"%"\$DC_PASSWORD" BASE-XCOPY "$*"
done
for mech in \
	"-k no" \
	"-k no --option=usespnego=no" \
	"-k no --option=gensec:spengo=no"; do
	signoptions="$mech --signing=off"
	name="smb.signing on with $signoptions"
	plantestsuite "$name local-creds" member $VALGRIND $smb4torture //"\$NETBIOSNAME"/tmp $signoptions -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" BASE-XCOPY "$*"
done
plantestsuite "smb.signing --signing=yes anon" dc $VALGRIND $smb4torture //"\$NETBIOSNAME"/tmp -k no --signing=yes -U% BASE-XCOPY "$*"
plantestsuite "smb.signing --signing=required anon" dc $VALGRIND $smb4torture //"\$NETBIOSNAME"/tmp -k no --signing=required -U% BASE-XCOPY "$*"
plantestsuite "smb.signing --signing=no anon" member $VALGRIND $smb4torture //"\$NETBIOSNAME"/tmp -k no --signing=no -U% BASE-XCOPY "$*"

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
	plantestsuite "nss.test using winbind" member $VALGRIND $nsstest4 $samba4bindir/shared/libnss_winbind.so
fi

SUBUNITRUN="$VALGRIND $PYTHON $samba4srcdir/scripting/bin/subunitrun"
plantestsuite "ldb.python" none PYTHONPATH="$PYTHONPATH:$samba4srcdir/lib/ldb/tests/python/" $PYTHON $samba4srcdir/lib/ldb/tests/python/api.py
plantestsuite "credentials.python" none PYTHONPATH="$PYTHONPATH:$samba4srcdir/auth/credentials/tests" $SUBUNITRUN bindings
plantestsuite "gensec.python" none PYTHONPATH="$PYTHONPATH:$samba4srcdir/auth/gensec/tests" $SUBUNITRUN bindings
plantestsuite "registry.python" none PYTHONPATH="$PYTHONPATH:$samba4srcdir/lib/registry/tests/" $SUBUNITRUN bindings
plantestsuite "tdb.python" none PYTHONPATH="$PYTHONPATH:../lib/tdb/python/tests" $SUBUNITRUN simple
plantestsuite "auth.python" none PYTHONPATH="$PYTHONPATH:$samba4srcdir/auth/tests/" $SUBUNITRUN bindings
plantestsuite "security.python" none PYTHONPATH="$PYTHONPATH:$samba4srcdir/libcli/security/tests" $SUBUNITRUN bindings
plantestsuite "misc.python" none $SUBUNITRUN samba.tests.dcerpc.misc
plantestsuite "param.python" none PYTHONPATH="$PYTHONPATH:$samba4srcdir/param/tests" $SUBUNITRUN bindings
plantestsuite "upgrade.python" none $SUBUNITRUN samba.tests.upgrade
plantestsuite "samba.python" none $SUBUNITRUN samba.tests
plantestsuite "provision.python" none $SUBUNITRUN samba.tests.provision
plantestsuite "samba3.python" none $SUBUNITRUN samba.tests.samba3
plantestsuite "samr.python" dc:local $SUBUNITRUN samba.tests.dcerpc.sam
plantestsuite "dsdb.python" dc:local $SUBUNITRUN samba.tests.dsdb
plantestsuite "netcmd.python" none $SUBUNITRUN samba.tests.netcmd
plantestsuite "dcerpc.bare.python" dc:local $SUBUNITRUN samba.tests.dcerpc.bare
plantestsuite "unixinfo.python" dc:local $SUBUNITRUN samba.tests.dcerpc.unix
plantestsuite "samdb.python" none $SUBUNITRUN samba.tests.samdb
plantestsuite "shares.python" none $SUBUNITRUN samba.tests.shares
plantestsuite "messaging.python" none PYTHONPATH="$PYTHONPATH:$samba4srcdir/lib/messaging/tests" $SUBUNITRUN bindings
plantestsuite "samba3sam.python" none PYTHONPATH="$PYTHONPATH:$samba4srcdir/dsdb/samdb/ldb_modules/tests" $SUBUNITRUN samba3sam
plantestsuite "subunit.python" none $SUBUNITRUN subunit
plantestsuite "rpcecho.python" dc:local $SUBUNITRUN samba.tests.dcerpc.rpcecho
plantestsuite "winreg.python" dc:local $SUBUNITRUN -U\$USERNAME%\$PASSWORD samba.tests.dcerpc.registry
plantestsuite "ldap.python" dc PYTHONPATH="$PYTHONPATH:../lib/subunit/python:../lib/testtools" $PYTHON $samba4srcdir/dsdb/tests/python/ldap.py \$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
plantestsuite "schemaInfo.python" dc PYTHONPATH="$PYTHONPATH:$samba4srcdir/dsdb/tests/python/" $SUBUNITRUN dsdb_schema_info -U"\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD"
plantestsuite "urgent_replication.python" dc PYTHONPATH="$PYTHONPATH:../lib/subunit/python:../lib/testtools" $PYTHON $samba4srcdir/dsdb/tests/python/urgent_replication.py \$PREFIX_ABS/dc/private/sam.ldb
for env in "dc" "fl2000dc" "fl2003dc" "fl2008r2dc"; do
    plantestsuite "ldap_schema.python" $env PYTHONPATH="$PYTHONPATH:../lib/subunit/python:../lib/testtools" $PYTHON $samba4srcdir/dsdb/tests/python/ldap_schema.py \$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
    plantestsuite "ldap.possibleInferiors.python" $env $PYTHON $samba4srcdir/dsdb/samdb/ldb_modules/tests/possibleinferiors.py ldap://\$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
    plantestsuite "ldap.secdesc.python" $env PYTHONPATH="$PYTHONPATH:../lib/subunit/python:../lib/testtools" $PYTHON $samba4srcdir/dsdb/tests/python/sec_descriptor.py \$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
    plantestsuite "ldap.acl.python" $env PYTHONPATH="$PYTHONPATH:../lib/subunit/python:../lib/testtools" $PYTHON $samba4srcdir/dsdb/tests/python/acl.py \$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
    plantestsuite "ldap.passwords.python" $env PYTHONPATH="$PYTHONPATH:../lib/subunit/python:../lib/testtools" $PYTHON $samba4srcdir/dsdb/tests/python/passwords.py \$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
done
plantestsuite "upgradeprovisiondc.python" dc:local $SUBUNITRUN samba.tests.upgradeprovisionneeddc
plantestsuite "upgradeprovisionnodc.python" none $SUBUNITRUN samba.tests.upgradeprovision
plantestsuite "xattr.python" none $SUBUNITRUN samba.tests.xattr
plantestsuite "ntacls.python" none $SUBUNITRUN samba.tests.ntacls
plantestsuite "deletetest.python" dc PYTHONPATH="$PYTHONPATH:../lib/subunit/python:../lib/testtools" $PYTHON $samba4srcdir/dsdb/tests/python/deletetest.py \$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
plantestsuite "policy.python" none PYTHONPATH="$PYTHONPATH:lib/policy/tests/python" $SUBUNITRUN bindings
plantestsuite "blackbox.samba3dump" none $PYTHON $samba4srcdir/scripting/bin/samba3dump $samba4srcdir/../testdata/samba3
rm -rf $PREFIX/upgrade
plantestsuite "blackbox.upgrade" none $PYTHON $samba4srcdir/setup/upgrade_from_s3 --targetdir=$PREFIX/upgrade $samba4srcdir/../testdata/samba3 ../testdata/samba3/smb.conf
rm -rf $PREFIX/provision
mkdir $PREFIX/provision
plantestsuite "blackbox.provision.py" none PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_provision.sh "$PREFIX/provision"
plantestsuite "blackbox.provision-backend.py" none PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_provision-backend.sh "$PREFIX/provision"
plantestsuite "blackbox.upgradeprovision.py" none PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_upgradeprovision.sh "$PREFIX/provision"
plantestsuite "blackbox.setpassword.py" none PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_setpassword.sh "$PREFIX/provision"
plantestsuite "blackbox.newuser.py" none PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_newuser.sh "$PREFIX/provision"
plantestsuite "blackbox.group.py" none PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_group.sh "$PREFIX/provision"
plantestsuite "blackbox.spn.py" dc:local PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_spn.sh "$PREFIX/dc"

# DRS python tests
plantestsuite "drs_delete_object.python" vampire_dc PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" DC1=\$DC_SERVER DC2=\$VAMPIRE_DC_SERVER $SUBUNITRUN delete_object -U"\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD"

# This makes sure we test the rid allocation code
t="RPC-SAMR-LARGE-DC"
plantestsuite "`normalize_testname $t.one`" vampire_dc $VALGRIND $smb4torture "\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
plantestsuite "`normalize_testname $t.two`" vampire_dc $VALGRIND $smb4torture "\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
