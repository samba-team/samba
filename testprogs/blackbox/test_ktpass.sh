#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_newuser.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

. `dirname $0`/subunit.sh


net="$BUILDDIR/bin/net"
samba4bindir="$BUILDDIR/bin"
samba4kinit="$samba4bindir/samba4kinit$EXEEXT"
CONFIG="--configfile=$PREFIX/dc/etc/smb.conf"

#two test for creating new user
#newuser  account is created with cn=Given Name Initials. Surname
#newuser1 account is created using cn=username
testit "newuser" $net newuser $CONFIG --given-name="User" --surname="Tester" --initials="T" --profile-path="\\\\myserver\\my\\profile" --script-path="\\\\myserver\\my\\script" --home-directory="\\\\myserver\\my\\homedir" --job-title="Tester" --department="Testing" --company="Samba.org" --description="Description" --mail-address="tester@samba.org" --internet-address="http://samba.org" --telephone-number="001122334455" --physical-delivery-office="101" --home-drive="H:" testuser testp@ssw0Rd|| failed=`expr $failed + 1`

KRB5CCNAME="$PREFIX/tmpccache"
export KRB5CCNAME
echo "testp@ssw0Rd" >$PREFIX/tmppassfile
testit "kinit with passwd" $samba4kinit -e arcfour-hmac-md5 --password-file=$PREFIX/tmppassfile   testuser@SAMBA.EXAMPLE.COM   || failed=`expr $failed + 1`
testit "ktpass" $BUILDDIR/scripting/bin/ktpass.sh --host LOCALDC --out $PREFIX/testuser.kt --princ testuser --pass "testp@ssw0Rd" --path-to-ldbsearch=$BUILDDIR/bin|| failed=`expr $failed + 1`

rm -f $KRB5CCNAME

testit "kinit with keytab" $samba4kinit -e arcfour-hmac-md5 --use-keytab -t $PREFIX/testuser.kt testuser@SAMBA.EXAMPLE.COM   || failed=`expr $failed + 1`

rm -f $PREFIX/tmpccache $PREFIX/testuser.kt
exit $failed
