#!/bin/sh

if [ $# -lt 2 ]; then
cat <<EOF
Usage: test_ntlm_auth_s3.sh PYTHON SRC3DIR NTLM_AUTH
EOF
exit 1;
fi

PYTHON=$1
SRC3DIR=$2
NTLM_AUTH=$3
DOMAIN=$4
USERNAME=$5
PASSWORD=$6
shift 6
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

SID=`eval $BINDIR/wbinfo -n $USERNAME | cut -d ' ' -f1`
BADSID=`eval $BINDIR/wbinfo -n $USERNAME | cut -d ' ' -f1 | sed 's/..$//'`

failed=0

test_ntlm_server_1_check_winbind_output_wrong_sid()
{
	tmpfile=$PREFIX/ntlm_commands

	# This isn't the correct password
	cat > $tmpfile <<EOF
Password: $PASSWORD
NT-Domain: $DOMAIN
Username: $USERNAME
Request-User-Session-Key: Yes
.
EOF
	cmd='$NTLM_AUTH "$@" --helper-protocol=ntlm-server-1 --require-membership-of=$BADSID < $tmpfile 2>&1'
	eval echo "$cmd"
	out=`eval $cmd`
	ret=$?
	rm -f $tmpfile

	if [ $ret != 0 ] ; then
		echo "$out"
		echo "command failed"
		false
		return
	fi

	echo "$out" | grep "Authenticated: No" >/dev/null 2>&1

	if [ $? = 0 ] ; then
		# failed to authenticate .. success
		true
	else
		echo "incorrectly gave a successful authentication"
		false
	fi
}

test_ntlm_server_1_check_winbind_output_fail()
{
	tmpfile=$PREFIX/ntlm_commands

	# This isn't the correct password
	cat > $tmpfile <<EOF
LANMAN-Challenge: 0123456789abcdef
NT-Response: 25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6
NT-Domain: $DOMAIN
Username: $USERNAME
Request-User-Session-Key: Yes
.
EOF
	cmd='$NTLM_AUTH "$@" --helper-protocol=ntlm-server-1 < $tmpfile 2>&1'
	eval echo "$cmd"
	out=`eval $cmd`
	ret=$?
	rm -f $tmpfile

	if [ $ret != 0 ] ; then
		echo "$out"
		echo "command failed"
		false
		return
	fi

	echo "$out" | grep "Authenticated: No" >/dev/null 2>&1

	if [ $? = 0 ] ; then
		# failed to authenticate .. success
		true
	else
		echo "incorrectly gave a successful authentication"
		false
	fi
}

# This should work even with NTLMv2
testit "ntlm_auth ntlm-server-1 with plaintext password against winbind but wrong sid" test_ntlm_server_1_check_winbind_output_wrong_sid || failed=`expr $failed + 1`
testit "ntlm_auth ntlm-server-1 with incorrect fixed password against winbind" test_ntlm_server_1_check_winbind_output_fail || failed=`expr $failed + 1`

testok $0 $failed
