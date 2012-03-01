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

failed=0

testit "ntlm_auth" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH $ADDARGS || failed=`expr $failed + 1`
# This should work even with NTLMv2
testit "ntlm_auth with specified domain" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH $ADDARGS --client-domain=fOo --server-domain=fOo || failed=`expr $failed + 1`
testit "ntlm_auth against winbindd" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH --client-username=$USERNAME --client-domain=$DOMAIN --client-password=$PASSWORD --server-use-winbindd $ADDARGS || failed=`expr $failed + 1`
testit "ntlm_auth with NTLMSSP client and gss-spnego server" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH $ADDARGS --client-domain=fOo --server-domain=fOo --client-helper=ntlmssp-client-1 --server-helper=gss-spnego || failed=`expr $failed + 1`
testit "ntlm_auth with NTLMSSP gss-spnego-client and gss-spnego server" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH $ADDARGS --client-domain=fOo --server-domain=fOo --client-helper=gss-spnego-client --server-helper=gss-spnego || failed=`expr $failed + 1`
testit "ntlm_auth with NTLMSSP gss-spnego-client and gss-spnego server against winbind" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH --client-username=$USERNAME --client-domain=$DOMAIN --client-password=$PASSWORD --server-use-winbindd --client-helper=gss-spnego-client --server-helper=gss-spnego $ADDARGS || failed=`expr $failed + 1`


testok $0 $failed
