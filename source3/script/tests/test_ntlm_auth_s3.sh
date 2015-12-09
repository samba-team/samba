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

test_plaintext_check_output_stdout()
{
	tmpfile=$PREFIX/ntlm_commands

	cat > $tmpfile <<EOF
$DOMAIN/$USERNAME $PASSWORD
EOF
	cmd='$NTLM_AUTH "$@" --require-membership-of=$SID --helper-protocol=squid-2.5-basic < $tmpfile 2>&1'
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

	echo "$out" | grep "OK" >/dev/null 2>&1

	if [ $? = 0 ] ; then
		# authenticated .. succeed
		true
	else
		echo failed to get successful authentication
		false
	fi
}

test_plaintext_check_output_fail()
{
	tmpfile=$PREFIX/ntlm_commands

	cat > $tmpfile <<EOF
$DOMAIN\\$USERNAME $PASSWORD
EOF
	cmd='$NTLM_AUTH "$@" --require-membership-of=$BADSID --helper-protocol=squid-2.5-basic < $tmpfile 2>&1'
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

	echo "$out" | grep "ERR" >/dev/null 2>&1

	if [ $? = 0 ] ; then
		# failed to authenticate .. success
		true
	else
		echo "incorrectly gave a successful authentication"
		false
	fi
}

test_ntlm_server_1_check_output()
{
	tmpfile=$PREFIX/ntlm_commands

	cat > $tmpfile <<EOF
LANMAN-Challenge: 0123456789abcdef
NT-Response: 25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6
NT-Domain: TEST
Username: testuser
Request-User-Session-Key: Yes
.
EOF
	cmd='$NTLM_AUTH "$@" --helper-protocol=ntlm-server-1  --password=SecREt01< $tmpfile 2>&1'
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

	echo "$out" | grep "User-Session-Key: 3F373EA8E4AF954F14FAA506F8EEBDC4" >/dev/null 2>&1

	if [ $? = 0 ] ; then
		# authenticated .. succeed
		true
	else
		echo failed to get successful authentication
		false
	fi
}

test_ntlm_server_1_check_output_fail()
{
	tmpfile=$PREFIX/ntlm_commands

	# Break the password with a leading A on the challenge
	cat > $tmpfile <<EOF
LANMAN-Challenge: A123456789abcdef
NT-Response: 25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6
NT-Domain: TEST
Username: testuser
Request-User-Session-Key: Yes
.
EOF
	cmd='$NTLM_AUTH "$@" --helper-protocol=ntlm-server-1 --password=SecREt01 < $tmpfile 2>&1'
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

test_ntlm_server_1_check_winbind_output()
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
	cmd='$NTLM_AUTH "$@" --helper-protocol=ntlm-server-1 --require-membership-of=$SID < $tmpfile 2>&1'
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

	echo "$out" | grep "Authenticated: Yes" >/dev/null 2>&1

	if [ $? = 0 ] ; then
		# authenticated .. success
		true
	else
		echo "Failed to authenticate the user or match with SID $SID"
		false
	fi
}

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

testit "ntlm_auth" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH $ADDARGS || failed=`expr $failed + 1`
# This should work even with NTLMv2
testit "ntlm_auth with specified domain" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH $ADDARGS --client-domain=fOo --server-domain=fOo || failed=`expr $failed + 1`
testit "ntlm_auth against winbindd" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH --client-username=$USERNAME --client-domain=$DOMAIN --client-password=$PASSWORD --server-use-winbindd $ADDARGS || failed=`expr $failed + 1`
testit "ntlm_auth with NTLMSSP client and gss-spnego server" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH $ADDARGS --client-domain=fOo --server-domain=fOo --client-helper=ntlmssp-client-1 --server-helper=gss-spnego || failed=`expr $failed + 1`
testit "ntlm_auth with NTLMSSP gss-spnego-client and gss-spnego server" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH $ADDARGS --client-domain=fOo --server-domain=fOo --client-helper=gss-spnego-client --server-helper=gss-spnego || failed=`expr $failed + 1`
testit "ntlm_auth with NTLMSSP gss-spnego-client and gss-spnego server against winbind" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH --client-username=$USERNAME --client-domain=$DOMAIN --client-password=$PASSWORD --server-use-winbindd --client-helper=gss-spnego-client --server-helper=gss-spnego $ADDARGS || failed=`expr $failed + 1`

testit "wbinfo store cached credentials" $BINDIR/wbinfo --ccache-save=$DOMAIN/$USERNAME%$PASSWORD || failed=`expr $failed + 1`
testit "ntlm_auth ccached credentials with NTLMSSP client and gss-spnego server" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH $ADDARGS --client-username=$USERNAME --client-domain=$DOMAIN --client-use-cached-creds --client-helper=ntlmssp-client-1 --server-helper=gss-spnego --server-use-winbindd || failed=`expr $failed + 1`

testit "ntlm_auth against winbindd with require-membership-of" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH --client-username=$USERNAME --client-domain=$DOMAIN --client-password=$PASSWORD --server-use-winbindd $ADDARGS --require-membership-of=$SID || failed=`expr $failed + 1`
testit "ntlm_auth with NTLMSSP gss-spnego-client and gss-spnego server against winbind with require-membership-of" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH --client-username=$USERNAME --client-domain=$DOMAIN --client-password=$PASSWORD --server-use-winbindd --client-helper=gss-spnego-client --server-helper=gss-spnego $ADDARGS --require-membership-of=$SID || failed=`expr $failed + 1`

testit_expect_failure "ntlm_auth against winbindd with failed require-membership-of" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH --client-username=$USERNAME --client-domain=$DOMAIN --client-password=$PASSWORD --server-use-winbindd $ADDARGS --require-membership-of=$BADSID && failed=`expr $failed + 1`
testit_expect_failure "ntlm_auth with NTLMSSP gss-spnego-client and gss-spnego server against winbind with failed require-membership-of" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH --client-username=$USERNAME --client-domain=$DOMAIN --client-password=$PASSWORD --server-use-winbindd --client-helper=gss-spnego-client --server-helper=gss-spnego $ADDARGS --require-membership-of=$BADSID && failed=`expr $failed + 1`

testit "ntlm_auth plaintext authentication with require-membership-of" test_plaintext_check_output_stdout || failed=`expr $failed + 1`
testit "ntlm_auth plaintext authentication with failed require-membership-of" test_plaintext_check_output_fail || failed=`expr $failed + 1`

testit "ntlm_auth ntlm-server-1 with fixed password" test_ntlm_server_1_check_output || failed=`expr $failed + 1`
testit "ntlm_auth ntlm-server-1 with incorrect fixed password" test_ntlm_server_1_check_output_fail || failed=`expr $failed + 1`
testit "ntlm_auth ntlm-server-1 with plaintext password against winbind" test_ntlm_server_1_check_winbind_output || failed=`expr $failed + 1`
testit "ntlm_auth ntlm-server-1 with plaintext password against winbind but wrong sid" test_ntlm_server_1_check_winbind_output_wrong_sid || failed=`expr $failed + 1`
testit "ntlm_auth ntlm-server-1 with incorrect fixed password against winbind" test_ntlm_server_1_check_winbind_output_fail || failed=`expr $failed + 1`

testok $0 $failed
