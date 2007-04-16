#!/bin/sh

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_kinit.sh SERVER USERNAME PASSWORD REALM PREFIX
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
REALM=$4
PREFIX=$5
shift 5
failed=0

testit() {
	name="$1"
	shift
	cmdline="$*"
	echo "test: $name"
	$cmdline
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
	fi
	return $status
}

KRB5CCNAME=`pwd`/tmpccache
export KRB5CCNAME

echo $PASSWORD > ./tmppassfile
testit "kinit with password" samba4kinit --password-file=./tmppassfile --request-pac $USERNAME@$REALM   || failed=`expr $failed + 1`
testit "kinit with pkinit" samba4kinit --request-pac --pk-user=FILE:$PREFIX/dc/private/tls/admincert.pem,$PREFIX/dc/private/tls/adminkey.pem $USERNAME@$REALM || failed=`expr $failed + 1`

echo ls | testit "Test login with kerberos ccache" $VALGRIND bin/smbclient $CONFIGURATION //$SERVER/tmp -k yes || failed=`expr $failed + 1`

testit "domain join with kerberos ccache" $VALGRIND bin/net join $DOMAIN $CONFIGURATION  -W "$DOMAIN" -k yes $@

rm -f tmpccfile tmppassfile
exit $failed
