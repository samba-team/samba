#!/bin/sh
# Blackbox tests for the samba_upgradedns
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2012 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_samba_upgradedns.sh SERVER REALM PREFIX PROVDIR
EOF
exit 1;
fi

SERVER=$1
REALM=$2
PREFIX=$3
PROVDIR=$4
shift 4
failed=0

samba4bindir="$BINDIR"
samba4srcdir="$SRCDIR/source4"
samba4kinit=kinit
if test -x $BINDIR/samba4kinit; then
	samba4kinit=$BINDIR/samba4kinit
fi


. `dirname $0`/subunit.sh

testit "run samba_upgradedns converting to bind9 DLZ" $samba4srcdir/scripting/bin/samba_upgradedns --dns-backend=BIND9_DLZ -s $PROVDIR/etc/smb.conf || failed=`expr $failed + 1`

testit "run samba_upgradedns converting to internal" $samba4srcdir/scripting/bin/samba_upgradedns --dns-backend=SAMBA_INTERNAL -s $PROVDIR/etc/smb.conf || failed=`expr $failed + 1`

testit "run samba_upgradedns converting to internal (2nd time)" $samba4srcdir/scripting/bin/samba_upgradedns --dns-backend=SAMBA_INTERNAL -s $PROVDIR/etc/smb.conf || failed=`expr $failed + 1`

testit "run samba_upgradedns converting to bind9 DLZ (2nd time)" $samba4srcdir/scripting/bin/samba_upgradedns --dns-backend=BIND9_DLZ -s $PROVDIR/etc/smb.conf || failed=`expr $failed + 1`

testit "run samba_upgradedns converting to bind9 DLZ (3rd time)" $samba4srcdir/scripting/bin/samba_upgradedns --dns-backend=BIND9_DLZ -s $PROVDIR/etc/smb.conf || failed=`expr $failed + 1`


exit $failed
