#!/bin/sh
ADDARGS="$*"

incdir=`dirname $0`
. $incdir/test_functions.sh

$incdir/../bin/smbtorture -V

TORTURE_QUICK="yes"
export TORTURE_QUICK

$SRCDIR/selftest/test_ejs.sh $CONFIGURATION
$SRCDIR/selftest/test_ldap.sh
$SRCDIR/selftest/test_nbt.sh

tests="BASE-UNLINK BASE-ATTR BASE-DELETE"
tests="$tests BASE-TCON BASE-OPEN"
tests="$tests BASE-CHKPATH RAW-QFSINFO RAW-QFILEINFO RAW-SFILEINFO"
tests="$tests RAW-MKDIR RAW-SEEK RAW-OPEN RAW-WRITE"
tests="$tests RAW-UNLINK RAW-READ RAW-CLOSE RAW-IOCTL RAW-RENAME"
tests="$tests RAW-EAS RAW-STREAMS"

for t in $tests; do
    plantest "$t" dc $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS $ADDARGS //\$SERVER/tmp -U"\$USERNAME"%"\$PASSWORD" $t
done

plantest "ntvfs/cifs BASE-OPEN" dc $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS $ADDARGS //\$NETBIOSNAME/cifs -U"\$USERNAME"%"\$PASSWORD" BASE-OPEN 

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests="RPC-ALTERCONTEXT RPC-JOIN RPC-ECHO RPC-SCHANNEL RPC-NETLOGON RPC-UNIXINFO RPC-HANDLES"
ncacn_ip_tcp_tests="RPC-ALTERCONTEXT RPC-JOIN RPC-ECHO RPC-HANDLES"
ncalrpc_tests="RPC-ECHO"

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
