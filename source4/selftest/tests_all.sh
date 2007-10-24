#!/bin/sh
if [ ! -n "$PERL" ]
then
	PERL=perl
fi

incdir=`dirname $0`
. $incdir/test_functions.sh

$incdir/../bin/smbtorture -V

$SRCDIR/selftest/test_ejs.sh $CONFIGURATION
$SRCDIR/selftest/test_ldap.sh 
$SRCDIR/selftest/test_nbt.sh "dc"
$SRCDIR/selftest/test_winbind.sh "dc"
$SRCDIR/selftest/test_rpc.sh

# Tests for the NET API

net=`$samba4bindir/smbtorture --list | grep ^NET-`

for t in $net; do
    plantest "$t" dc $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS "\$SERVER[$VALIDATE]" -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" $t "$*"
done

$SRCDIR/selftest/test_session_key.sh
$SRCDIR/selftest/test_echo.sh

# Tests against the NTVFS POSIX backend
smb2=`$samba4bindir/smbtorture --list | grep "^SMB2-" | xargs`
raw=`$samba4bindir/smbtorture --list | grep "^RAW-" | xargs`
base=`$samba4bindir/smbtorture --list | grep "^BASE-" | xargs`

for t in $base $raw $smb2; do
    plantest "$t" dc $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS $ADDARGS //\$SERVER/tmp -U"\$USERNAME"%"\$PASSWORD" $t
done

# Tests against the NTVFS CIFS backend
for t in $base $raw; do
    plantest "ntvfs/cifs $t" dc $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS //\$NETBIOSNAME/cifs -U"\$USERNAME"%"\$PASSWORD" $t
done

# Local tests

for t in `$samba4bindir/smbtorture --list | grep "^LOCAL-" | xargs`; do
	plantest "$t" none $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS ncalrpc: $t "$*"
done

if test -f $samba4bindir/tdbtorture
then
	plantest "tdb stress" none $VALGRIND $samba4bindir/tdbtorture
fi

# Pidl tests

if test x"${PIDL_TESTS_SKIP}" = x"yes"; then
   echo "Skipping pidl tests - PIDL_TESTS_SKIP=yes"
elif $PERL -e 'eval require Test::More;' > /dev/null 2>&1; then
  for f in $samba4srcdir/pidl/tests/*.pl; do
     plantest "pidl/`basename $f`" none $PERL $f "|" $samba4srcdir/script/harness2subunit.pl
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
plantest "blackbox.nmblookup:dc" dc $bbdir/test_nmblookup.sh "\$NETBIOSNAME" "\$NETBIOSALIAS" "\$SERVER" "\$SERVER_IP" 
plantest "blackbox.nmblookup:member" member $bbdir/test_nmblookup.sh "\$NETBIOSNAME" "\$NETBIOSALIAS" "\$SERVER" "\$SERVER_IP"

# Tests using the "Simple" NTVFS backend

for t in "BASE-RW1"; do
    plantest "ntvfs/simple $t" dc $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS $ADDARGS //\$SERVER/simple -U"\$USERNAME"%"\$PASSWORD" $t
done

$SRCDIR/selftest/test_s3upgrade.sh $PREFIX/upgrade

# Domain Member Tests

plantest "RPC-ECHO against member server with local creds" member $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" RPC-ECHO "$*"
plantest "RPC-ECHO against member server with domain creds" member $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS ncacn_np:"\$NETBIOSNAME" -U"\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD" RPC-ECHO "$*"
plantest "RPC-SAMR against member server with local creds" member $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR" "$*"
plantest "RPC-SAMR-USERS against member server with local creds" member $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR-USERS" "$*"
plantest "RPC-SAMR-PASSWORDS against member server with local creds" member $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR-PASSWORDS" "$*"
plantest "wbinfo -a against member server with domain creds" member $VALGRIND $samba4bindir/wbinfo -a "\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD"

$SRCDIR/selftest/test_nbt.sh "member"
$SRCDIR/selftest/test_winbind.sh "member"
