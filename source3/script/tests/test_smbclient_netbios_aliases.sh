#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_smbclient.sh smbclient3 SERVER USERNAME PASSWORD PREFIX <smbclient args>
EOF
exit 1;
fi

SMBCLIENT3=$1
SERVER=$2
USERNAME=$3
PASSWORD=$4
PREFIX=$5
shift 5
ADDARGS="$*"

samba4bindir="$BINDIR"
samba4srcdir="$SRCDIR/source4"
samba4kinit=kinit
if test -x $BINDIR/samba4kinit; then
	samba4kinit=$BINDIR/samba4kinit
fi

KRB5CCNAME_PATH="$PREFIX/test_smbclient_netbios_aliases_krb5ccache"
rm -rf $KRB5CCNAME_PATH

KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

echo $PASSWORD > $PREFIX/tmppassfile
testit "kinit" $samba4kinit --password-file=$PREFIX/tmppassfile $USERNAME || failed=`expr $failed + 1`
rm -f $PREFIX/tmppassfile
testit "smbclient" $VALGRIND $SMBCLIENT3 -k //$SERVER/tmp -c 'ls' $ADDARGS || failed=`expr $failed + 1`

rm -rf $KRB5CCNAME_PATH

testok $0 $failed
