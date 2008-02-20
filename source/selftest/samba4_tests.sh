#!/bin/sh
# This script generates a list of testsuites that should be run as part of 
# the Samba 4 test suite.

# The output of this script is parsed by selftest.pl, which then decides 
# which of the tests to actually run. It will, for example, skip all tests 
# listed in samba4-skip or only run a subset during "make quicktest".

# The idea is that this script outputs all of the tests of Samba 4, not 
# just those that are known to pass, and list those that should be skipped 
# or are known to file in samba4-skip/samba4-knownfail. This makes it 
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

incdir=`dirname $0`

plantest() {
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

normalize_testname() {
	name=$1
	shift 1
	echo $name | tr "A-Z-" "a-z."
}

plansmbtorturetest() {
	name=$1
	env=$2
	shift 2
	other_args="$*"
	modname=`normalize_testname $name`
	cmdline="$VALGRIND $smb4torture $other_args $name"
	plantest "$modname" "$env" $cmdline
}

$incdir/../bin/smbtorture -V

samba4srcdir=$incdir/..
samba4bindir=$samba4srcdir/bin
SCRIPTDIR=$samba4srcdir/../testprogs/ejs
smb4torture="$samba4bindir/smbtorture $TORTURE_OPTIONS"

plantest "js.base" dc "$SCRIPTDIR/base.js" $CONFIGURATION
plantest "js.samr" dc "$SCRIPTDIR/samr.js" $CONFIGURATION ncalrpc: -U\$USERNAME%\$PASSWORD
plantest "js.echo" dc "$SCRIPTDIR/echo.js" $CONFIGURATION ncalrpc: -U\$USERNAME%\$PASSWORD
#plantest "ejsnet.js" dc "$SCRIPTDIR/ejsnet.js" $CONFIGURATION -U\$USERNAME%\$PASSWORD \$DOMAIN ejstestuser
plantest "js.ldb" none "$SCRIPTDIR/ldb.js" `pwd` $CONFIGURATION -d 10
plantest "js.winreg" dc $samba4srcdir/scripting/bin/winreg $CONFIGURATION ncalrpc: 'HKLM' -U\$USERNAME%\$PASSWORD

# Simple tests for LDAP and CLDAP

for options in "" "--option=socket:testnonblock=true" "-U\$USERNAME%\$PASSWORD --option=socket:testnonblock=true" "-U\$USERNAME%\$PASSWORD"; do
    plantest "ldb.ldap with options $options" dc $samba4srcdir/../testprogs/blackbox/test_ldb.sh ldap \$SERVER_IP $options
done
# see if we support ldaps
if grep ENABLE_GNUTLS.1 include/config.h > /dev/null; then
    for options in "" "-U\$USERNAME%\$PASSWORD"; do
	plantest "ldb.ldaps with options $options" dc $samba4srcdir/../testprogs/blackbox/test_ldb.sh ldaps \$SERVER_IP $options
    done
fi
for t in LDAP-CLDAP LDAP-BASIC LDAP-SCHEMA LDAP-UPTODATEVECTOR
do
	plansmbtorturetest "$t" dc "-U\$USERNAME%\$PASSWORD" //\$SERVER_IP/_none_
done

# only do the ldb tests when not in quick mode - they are quite slow, and ldb
# is now pretty well tested by the rest of the quick tests anyway
LDBDIR=$samba4srcdir/lib/ldb
export LDBDIR
plantest "ldb" none TEST_DATA_PREFIX=\$PREFIX $LDBDIR/tests/test-tdb.sh
plantest "js.ldap" dc $SCRIPTDIR/ldap.js $CONFIGURATION -d 10 \$SERVER -U\$USERNAME%\$PASSWORD

# Tests for RPC

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests="RPC-SCHANNEL RPC-JOIN RPC-LSA RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND RPC-NETLOGON RPC-HANDLES RPC-SAMSYNC RPC-SAMBA3SESSIONKEY RPC-SAMBA3-GETUSERNAME RPC-SAMBA3-LSA RPC-BINDSAMBA3 RPC-NETLOGSAMBA3 RPC-ASYNCBIND RPC-LSALOOKUP RPC-LSA-GETUSER RPC-SCHANNEL2 RPC-AUTHCONTEXT"
ncalrpc_tests="RPC-SCHANNEL RPC-JOIN RPC-LSA RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND RPC-NETLOGON RPC-DRSUAPI RPC-ASYNCBIND RPC-LSALOOKUP RPC-LSA-GETUSER RPC-SCHANNEL2 RPC-AUTHCONTEXT"
ncacn_ip_tcp_tests="RPC-SCHANNEL RPC-JOIN RPC-LSA RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND RPC-NETLOGON RPC-HANDLES RPC-DSSYNC RPC-ASYNCBIND RPC-LSALOOKUP RPC-LSA-GETUSER RPC-SCHANNEL2 RPC-AUTHCONTEXT"
slow_ncacn_np_tests="RPC-SAMLOGON RPC-SAMR RPC-SAMR-USERS RPC-SAMR-PASSWORDS"
slow_ncalrpc_tests="RPC-SAMR RPC-SAMR-PASSWORDS"
slow_ncacn_ip_tcp_tests="RPC-SAMR RPC-SAMR-PASSWORDS RPC-CRACKNAMES"

all_tests="$ncalrpc_tests $ncacn_np_tests $ncacn_ip_tcp_tests $slow_ncalrpc_tests $slow_ncacn_np_tests $slow_ncacn_ip_tcp_tests RPC-SECRETS RPC-SAMBA3-SHARESEC"

# Make sure all tests get run
for t in `$smb4torture --list | grep "^RPC-"`
do
	echo $all_tests | grep $t  > /dev/null
	if [ $? -ne 0 ]
	then
		auto_rpc_tests="$auto_rpc_tests $t"
	fi
done

for bindoptions in seal,padcheck $VALIDATE bigendian; do
 for transport in ncalrpc ncacn_np ncacn_ip_tcp; do
     case $transport in
	 ncalrpc) tests=$ncalrpc_tests ;;
	 ncacn_np) tests=$ncacn_np_tests ;;
	 ncacn_ip_tcp) tests=$ncacn_ip_tcp_tests ;;
     esac
   for t in $tests; do
    plantest "`normalize_testname $t` on $transport with $bindoptions" dc $VALGRIND $smb4torture $transport:"\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
   done
   plantest "rpc.samba3.sharesec on $transport with $bindoptions" dc $VALGRIND $smb4torture $transport:"\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN --option=torture:share=tmp RPC-SAMBA3-SHARESEC "$*"
 done
done

for bindoptions in "" $VALIDATE bigendian; do
 for t in $auto_rpc_tests; do
  plantest "`normalize_testname $t` with $bindoptions" dc $VALGRIND $smb4torture "\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
 done
done

for bindoptions in connect $VALIDATE ; do
 for transport in ncalrpc ncacn_np ncacn_ip_tcp; do
     case $transport in
	 ncalrpc) tests=$slow_ncalrpc_tests ;;
	 ncacn_np) tests=$slow_ncacn_np_tests ;;
	 ncacn_ip_tcp) tests=$slow_ncacn_ip_tcp_tests ;;
     esac
   for t in $tests; do
    plantest "`normalize_testname $t` on $transport with $bindoptions" dc $VALGRIND $smb4torture $transport:"\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
   done
 done
done


# Tests for the NET API

net=`$smb4torture --list | grep ^NET-`

for t in $net; do
    plansmbtorturetest "$t" dc "\$SERVER[$VALIDATE]" -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" "$*"
done

# Tests for session keys

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
	name="rpc.secrets on $transport with $bindoptions with $ntlmoptions"
   plantest "$name" dc $smb4torture $transport:"\$SERVER[$bindoptions]"  $ntlmoptions -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN --option=gensec:target_hostname=\$NETBIOSNAME RPC-SECRETS "$*"
done
plantest "rpc.secrets on $transport with $bindoptions with Kerberos" dc $smb4torture $transport:"\$SERVER[$bindoptions]" -k yes -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN "--option=gensec:target_hostname=\$NETBIOSNAME" RPC-SECRETS "$*"
plantest "rpc.secrets on $transport with $bindoptions with Kerberos - use target principal" dc $smb4torture $transport:"\$SERVER[$bindoptions]" -k yes -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN "--option=clientusespnegoprincipal=yes" "--option=gensec:target_hostname=\$NETBIOSNAME" RPC-SECRETS "$*"
plantest "rpc.secrets on $transport with Kerberos - use Samba3 style login" dc $smb4torture $transport:"\$SERVER" -k yes -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" "--option=gensec:fake_gssapi_krb5=yes" "--option=gensec:gssapi_krb5=no" "--option=gensec:target_hostname=\$NETBIOSNAME" "RPC-SECRETS-none*" "$*"
plantest "rpc.secrets on $transport with Kerberos - use Samba3 style login, use target principal" dc $smb4torture $transport:"\$SERVER" -k yes -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" "--option=clientusespnegoprincipal=yes" "--option=gensec:fake_gssapi_krb5=yes" "--option=gensec:gssapi_krb5=no" "--option=gensec:target_hostname=\$NETBIOSNAME" "RPC-SECRETS-none*" "$*"

# Echo tests
transports="ncacn_np ncacn_ip_tcp ncalrpc"

for transport in $transports; do
 for bindoptions in connect spnego spnego,sign spnego,seal $VALIDATE padcheck bigendian bigendian,seal; do
  for ntlmoptions in \
        "--option=socket:testnonblock=True --option=torture:quick=yes"; do
   plantest "rpc.echo on $transport with $bindoptions and $ntlmoptions" dc $smb4torture $transport:"\$SERVER[$bindoptions]" $ntlmoptions -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" RPC-ECHO "$*"
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
   plantest "rpc.echo on $transport with $bindoptions and $ntlmoptions" dc $smb4torture $transport:"\$SERVER[$bindoptions]" $ntlmoptions -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN RPC-ECHO "$*"
  done
 done
done

plantest "rpc.echo on ncacn_np over smb2" dc $smb4torture ncacn_np:"\$SERVER[smb2]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN RPC-ECHO "$*"

# Tests against the NTVFS POSIX backend
smb2=`$smb4torture --list | grep "^SMB2-" | xargs`
raw=`$smb4torture --list | grep "^RAW-" | xargs`
base=`$smb4torture --list | grep "^BASE-" | xargs`

for t in $base $raw $smb2; do
    plansmbtorturetest "$t" dc $ADDARGS //\$SERVER/tmp -U"\$USERNAME"%"\$PASSWORD"
done

rap=`$smb4torture --list | grep "^RAP-" | xargs`
for t in $rap; do
    plansmbtorturetest "$t" dc $ADDARGS //\$SERVER/IPC\\\$ -U"\$USERNAME"%"\$PASSWORD"
done

# Tests against the NTVFS CIFS backend
for t in $base $raw; do
    plantest "ntvfs.cifs.`normalize_testname $t`" dc $VALGRIND $smb4torture //\$NETBIOSNAME/cifs -U"\$USERNAME"%"\$PASSWORD" $t
done

# Local tests

for t in `$smb4torture --list | grep "^LOCAL-" | xargs`; do
	plansmbtorturetest "$t" none ncalrpc: "$*"
done

if test -f $samba4bindir/tdbtorture
then
	plantest "tdb.stress" none $VALGRIND $samba4bindir/tdbtorture
fi

# Pidl tests

if test x"${PIDL_TESTS_SKIP}" = x"yes"; then
   echo "Skipping pidl tests - PIDL_TESTS_SKIP=yes"
elif $PERL -e 'eval require Test::More;' > /dev/null 2>&1; then
  for f in $samba4srcdir/pidl/tests/*.pl; do
     plantest "pidl.`basename $f .pl`" none $PERL $f "|" $samba4srcdir/script/harness2subunit.pl
  done
else 
   echo "Skipping pidl tests - Test::More not installed"
fi

# Blackbox Tests:
# tests that interact directly with the command-line tools rather than using 
# the API

bbdir=$incdir/../../testprogs/blackbox

plantest "blackbox.smbclient" dc $bbdir/test_smbclient.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$PREFIX" 
plantest "blackbox.kinit" dc $bbdir/test_kinit.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$REALM" "\$DOMAIN" "$PREFIX" 
plantest "blackbox.cifsdd" dc $bbdir/test_cifsdd.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" 
plantest "blackbox.nmblookup" dc $samba4srcdir/utils/tests/test_nmblookup.sh "\$NETBIOSNAME" "\$NETBIOSALIAS" "\$SERVER" "\$SERVER_IP" 
plantest "blackbox.nmblookup" member $samba4srcdir/utils/tests/test_nmblookup.sh "\$NETBIOSNAME" "\$NETBIOSALIAS" "\$SERVER" "\$SERVER_IP"
plantest "blackbox.locktest" dc $bbdir/test_locktest.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$PREFIX"
plantest "blackbox.masktest" dc $bbdir/test_masktest.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$PREFIX"
plantest "blackbox.gentest" dc $bbdir/test_gentest.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$PREFIX"

# Tests using the "Simple" NTVFS backend

for t in "BASE-RW1"; do
    plantest "ntvfs.simple.`normalize_testname $t`" dc $VALGRIND $smb4torture $ADDARGS //\$SERVER/simple -U"\$USERNAME"%"\$PASSWORD" $t
done

DATADIR=$samba4srcdir/../testdata

plantest "js.samba3sam" none $SCRIPTDIR/samba3sam.js $CONFIGURATION `pwd` $DATADIR/samba3/

# Domain Member Tests

plantest "rpc.echo against member server with local creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" RPC-ECHO "$*"
plantest "rpc.echo against member server with domain creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD" RPC-ECHO "$*"
plantest "rpc.samr against member server with local creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR" "$*"
plantest "rpc.samr.users against member server with local creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR-USERS" "$*"
plantest "rpc.samr.passwords against member server with local creds" member $VALGRIND $smb4torture ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR-PASSWORDS" "$*"
plantest "wbinfo -a against member server with domain creds" member $VALGRIND $samba4bindir/wbinfo -a "\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD"

NBT_TESTS=`$smb4torture --list | grep "^NBT-" | xargs`

for t in $NBT_TESTS; do
	plansmbtorturetest "$t" dc //\$SERVER/_none_ -U\$USERNAME%\$PASSWORD 
done

WB_OPTS="--option=\"torture:strict mode=yes\""
WB_OPTS="${WB_OPTS} --option=\"torture:timelimit=1\""
WB_OPTS="${WB_OPTS} --option=\"torture:winbindd separator=\\\\\""
WB_OPTS="${WB_OPTS} --option=\"torture:winbindd private pipe dir=\$WINBINDD_PRIV_PIPE_DIR\""
WB_OPTS="${WB_OPTS} --option=\"torture:winbindd netbios name=\$SERVER\""
WB_OPTS="${WB_OPTS} --option=\"torture:winbindd netbios domain=\$DOMAIN\""

WINBIND_STRUCT_TESTS=`$smb4torture --list | grep "^WINBIND-STRUCT" | xargs`
WINBIND_NDR_TESTS=`$smb4torture --list | grep "^WINBIND-NDR" | xargs`
for env in dc member; do
	for t in $WINBIND_STRUCT_TESTS; do
		plansmbtorturetest $t $env $WB_OPTS //_none_/_none_
	done

	for t in $WINBIND_NDR_TESTS; do
		plansmbtorturetest $t $env $WB_OPTS //_none_/_none_
	done
done

if test -f $samba4bindir/nsstest 
then
	plantest "nss.test using winbind" member $VALGRIND $samba4bindir/nsstest $samba4bindir/shared/libnss_winbind.so
fi

PYTHON=bin/smbpython
SUBUNITRUN="$PYTHON ./scripting/bin/subunitrun"
plantest "ldb.python" none PYTHONPATH="$PYTHONPATH:lib/ldb/tests/python/" $SUBUNITRUN api
plantest "credentials.python" none PYTHONPATH="$PYTHONPATH:auth/credentials/tests" $SUBUNITRUN bindings
plantest "registry.python" none PYTHONPATH="$PYTHONPATH:lib/registry/tests/" $SUBUNITRUN bindings
plantest "tdb.python" none PYTHONPATH="$PYTHONPATH:lib/tdb/python/tests" $SUBUNITRUN simple
plantest "auth.python" none PYTHONPATH="$PYTHONPATH:auth/tests/" $SUBUNITRUN bindings
plantest "security.python" none PYTHONPATH="$PYTHONPATH:libcli/security/tests" $SUBUNITRUN bindings
plantest "param.python" none PYTHONPATH="$PYTHONPATH:param/tests" $SUBUNITRUN bindings
plantest "upgrade.python" none $SUBUNITRUN samba.tests.upgrade
plantest "samba.python" none $SUBUNITRUN samba.tests
plantest "provision.python" none $SUBUNITRUN samba.tests.provision
plantest "samba3.python" none $SUBUNITRUN samba.tests.samba3
plantest "samr.python" dc $SUBUNITRUN samba.tests.dcerpc.sam
plantest "samdb.python" dc $SUBUNITRUN samba.tests.samdb
plantest "events.python" none PYTHONPATH="$PYTHONPATH:lib/events" $SUBUNITRUN tests
plantest "samba3sam.python" none PYTHONPATH="$PYTHONPATH:dsdb/samdb/ldb_modules/tests" $SUBUNITRUN samba3sam
plantest "rpcecho.python" dc $SUBUNITRUN samba.tests.dcerpc.rpcecho
plantest "winreg.python" dc $SUBUNITRUN samba.tests.dcerpc.registry
plantest "ldap.python" dc $PYTHON $samba4srcdir/lib/ldb/tests/python/ldap.py $CONFIGURATION \$SERVER -U\$USERNAME%\$PASSWORD -W \$DOMAIN
plantest "blackbox.samba3dump" none $PYTHON scripting/bin/samba3dump $samba4srcdir/../testdata/samba3
rm -rf $PREFIX/upgrade
plantest "blackbox.upgrade" none $PYTHON setup/upgrade.py $CONFIGURATION --targetdir=$PREFIX/upgrade ../testdata/samba3 ../testdata/samba3/smb.conf
rm -rf $PREFIX/provision
mkdir $PREFIX/provision
plantest "blackbox.provision.py" none PYTHON="$PYTHON" $samba4srcdir/setup/tests/blackbox_provision.sh "$PREFIX/provision" "$CONFIGURATION" 
