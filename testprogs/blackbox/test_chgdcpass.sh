#!/bin/sh
# Blackbox tests for kinit and kerberos integration with smbclient etc
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_kinit.sh SERVER USERNAME REALM DOMAIN PREFIX
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
REALM=$3
DOMAIN=$4
PREFIX=$5
ENCTYPE=$6
PROVDIR=$7
shift 7
failed=0

samba4bindir="$BUILDDIR/bin"
samba4kinit="$samba4bindir/samba4kinit$EXEEXT"

. `dirname $0`/subunit.sh

enctype="-e $ENCTYPE"

KRB5CCNAME="$PREFIX/tmpccache"
export KRB5CCNAME
rm -f $KRB5CCNAME
testit "kinit with keytab" $samba4kinit $enctype -t $PROVDIR/private/secrets.keytab --use-keytab $USERNAME   || failed=`expr $failed + 1`
testit "change dc password" ./scripting/devel/chgtdcpass -s $PROVDIR/etc/smb.conf || failed=`expr $failed + 1`
testit "kinit with keytab" $samba4kinit $enctype -t $PROVDIR/private/secrets.keytab --use-keytab $USERNAME   || failed=`expr $failed + 1`
rm -f $KRB5CCNAME

rm -f $PREFIX/tmpccache tmpccfile tmppassfile tmpuserpassfile tmpuserccache tmpkpasswdscript
exit $failed
