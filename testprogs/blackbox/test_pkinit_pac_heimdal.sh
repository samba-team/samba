#!/bin/sh
# Blackbox tests for pkinit and pac verification
# Copyright (C) 2006-2008 Stefan Metzmacher

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_pkinit_pac_heimdal.sh SERVER USERNAME PASSWORD REALM DOMAIN PREFIX ENCTYPE
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
REALM=$4
DOMAIN=$5
PREFIX=$6
ENCTYPE=$7
shift 7
failed=0

samba4bindir="$BINDIR"
samba4srcdir="$SRCDIR/source4"
samba4kinit=kinit
if test -x $BINDIR/samba4kinit; then
	samba4kinit=$BINDIR/samba4kinit
fi

smbtorture4="$samba4bindir/smbtorture"

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

enctype="-e $ENCTYPE"
unc="//$SERVER/tmp"

KRB5CCNAME_PATH="$PREFIX/tmpccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME
rm -f $KRB5CCNAME_PATH
PASSFILE_PATH="$PREFIX/tmppassfile"
rm -f $PASSFILE_PATH
echo $PASSWORD > $PASSFILE_PATH

USER_PRINCIPAL_NAME=`echo "${USERNAME}@${REALM}" | tr A-Z a-z`
PKUSER="--pk-user=FILE:$PREFIX/pkinit/USER-${USER_PRINCIPAL_NAME}-cert.pem,$PREFIX/pkinit/USER-${USER_PRINCIPAL_NAME}-private-key.pem"

testit "STEP1 kinit with pkinit (name specified) " $samba4kinit $enctype --request-pac --renewable $PKUSER $USERNAME@$REALM || failed=`expr $failed + 1`
testit "STEP1 remote.pac verification" $smbtorture4 ncacn_np:$SERVER rpc.pac --workgroup=$DOMAIN -U$USERNAME%$PASSWORD --krb5-ccache=$KRB5CCNAME --option=torture:pkinit_in_use=yes || failed=`expr $failed + 1`

rm -f $PASSFILE_PATH
rm -f $KRB5CCNAME_PATH
exit $failed
