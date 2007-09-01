#!/bin/sh

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests="RPC-SPOOLSS RPC-SRVSVC RPC-UNIXINFO RPC-SCHANNEL RPC-JOIN RPC-LSA RPC-ECHO RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND RPC-NETLOGON RPC-MGMT RPC-HANDLES RPC-WINREG RPC-WKSSVC RPC-SVCCTL RPC-EPMAPPER RPC-INITSHUTDOWN RPC-EVENTLOG RPC-ATSVC RPC-SAMSYNC RPC-DFS RPC-OXIDRESOLVE RPC-REMACT RPC-SAMBA3SESSIONKEY RPC-SAMBA3-SRVSVC RPC-SAMBA3-SHARESEC RPC-SAMBA3-GETUSERNAME RPC-SAMBA3-LSA RPC-SAMBA3-SPOOLSS RPC-SAMBA3-WKSSVC RPC-BINDSAMBA3 RPC-NETLOGSAMBA3 RPC-SAMBA3-WINREG RPC-ASYNCBIND RPC-LSALOOKUP RPC-LSA-GETUSER RPC-SCHANNEL2 RPC-BENCH-RPC RPC-SCANNER RPC-AUTOIDL RPC-AUTHCONTEXT"
ncalrpc_tests="RPC-MGMT RPC-UNIXINFO RPC-SCHANNEL RPC-JOIN RPC-LSA RPC-ECHO RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND RPC-NETLOGON RPC-WINREG RPC-WKSSVC RPC-SVCCTL RPC-EPMAPPER RPC-EVENTLOG RPC-ATSVC RPC-INITSHUTDOWN RPC-DFS RPC-OXIDRESOLVE RPC-REMACT RPC-DRSUAPI RPC-ASYNCBIND RPC-LSALOOKUP RPC-LSA-GETUSER RPC-SCHANNEL2 RPC-BENCH-RPC RPC-SCANNER RPC-AUTOIDL RPC-AUTHCONTEXT"
ncacn_ip_tcp_tests="RPC-UNIXINFO RPC-SCHANNEL RPC-JOIN RPC-LSA RPC-ECHO RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND RPC-NETLOGON RPC-MGMT RPC-HANDLES RPC-WINREG RPC-WKSSVC RPC-SVCCTL RPC-EPMAPPER RPC-ATSVC RPC-EVENTLOG RPC-DSSYNC RPC-DFS RPC-OXIDRESOLVE RPC-REMACT RPC-ASYNCBIND RPC-LSALOOKUP RPC-LSA-GETUSER RPC-SCHANNEL2 RPC-BENCH-RPC RPC-SCANNER RPC-AUTOIDL RPC-AUTHCONTEXT"
slow_ncacn_np_tests="RPC-SAMLOGON RPC-SAMR RPC-SAMR-USERS RPC-SAMR-PASSWORDS RPC-COUNTCALLS"
slow_ncalrpc_tests="RPC-SAMR RPC-SAMR-PASSWORDS RPC-COUNTCALLS RPC-CRACKNAMES"
slow_ncacn_ip_tcp_tests="RPC-SAMR RPC-SAMR-PASSWORDS RPC-COUNTCALLS RPC-CRACKNAMES"

incdir=`dirname $0`
. $incdir/test_functions.sh

all_tests="$ncalrpc_tests $ncacn_np_tests $ncacn_ip_tcp_tests $slow_ncalrpc_tests $slow_ncacn_np_tests $slow_ncacn_ip_tcp_tests RPC-SECRETS"

# Make sure all tests get run
for t in `$samba4bindir/smbtorture --list | grep "^RPC-"`
do
	if ! echo $all_tests | grep $t  > /dev/null
	then
		echo "SKIP: $t"
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
    name="$t on $transport with $bindoptions"
    plantest "$name" dc $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS $transport:"\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
   done
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
    name="$t on $transport with $bindoptions"
    plantest "$name" dc $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS $transport:"\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
   done
 done
done
