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

test_interactive_prompt_stdout()
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

test_interactive_prompt_stdout_fail()
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

testit "ntlm_auth" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH $ADDARGS || failed=`expr $failed + 1`
# This should work even with NTLMv2
testit "ntlm_auth with specified domain" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH $ADDARGS --client-domain=fOo --server-domain=fOo || failed=`expr $failed + 1`
testit "ntlm_auth against winbindd" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH --client-username=$USERNAME --client-domain=$DOMAIN --client-password=$PASSWORD --server-use-winbindd $ADDARGS || failed=`expr $failed + 1`
testit "ntlm_auth with NTLMSSP client and gss-spnego server" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH $ADDARGS --client-domain=fOo --server-domain=fOo --client-helper=ntlmssp-client-1 --server-helper=gss-spnego || failed=`expr $failed + 1`
testit "ntlm_auth with NTLMSSP gss-spnego-client and gss-spnego server" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH $ADDARGS --client-domain=fOo --server-domain=fOo --client-helper=gss-spnego-client --server-helper=gss-spnego || failed=`expr $failed + 1`
testit "ntlm_auth with NTLMSSP gss-spnego-client and gss-spnego server against winbind" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH --client-username=$USERNAME --client-domain=$DOMAIN --client-password=$PASSWORD --server-use-winbindd --client-helper=gss-spnego-client --server-helper=gss-spnego $ADDARGS || failed=`expr $failed + 1`


testit "ntlm_auth against winbindd with require-membership-of" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH --client-username=$USERNAME --client-domain=$DOMAIN --client-password=$PASSWORD --server-use-winbindd $ADDARGS --require-membership-of=$SID || failed=`expr $failed + 1`
testit "ntlm_auth with NTLMSSP gss-spnego-client and gss-spnego server against winbind with require-membership-of" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH --client-username=$USERNAME --client-domain=$DOMAIN --client-password=$PASSWORD --server-use-winbindd --client-helper=gss-spnego-client --server-helper=gss-spnego $ADDARGS --require-membership-of=$SID || failed=`expr $failed + 1`

testit_expect_failure "ntlm_auth against winbindd with failed require-membership-of" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH --client-username=$USERNAME --client-domain=$DOMAIN --client-password=$PASSWORD --server-use-winbindd $ADDARGS --require-membership-of=$BADSID && failed=`expr $failed + 1`
testit_expect_failure "ntlm_auth with NTLMSSP gss-spnego-client and gss-spnego server against winbind with failed require-membership-of" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH --client-username=$USERNAME --client-domain=$DOMAIN --client-password=$PASSWORD --server-use-winbindd --client-helper=gss-spnego-client --server-helper=gss-spnego $ADDARGS --require-membership-of=$BADSID && failed=`expr $failed + 1`

testit "ntlm_auth plaintext authentication with require-membership-of" test_interactive_prompt_stdout || failed=`expr $failed + 1`
testit "ntlm_auth plaintext authentication with failed require-membership-of" test_interactive_prompt_stdout_fail || failed=`expr $failed + 1`

testok $0 $failed
