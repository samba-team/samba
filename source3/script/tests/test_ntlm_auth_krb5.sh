#!/bin/sh

if [ $# -lt 2 ]; then
cat <<EOF
Usage: test_ntlm_auth_s3.sh PYTHON SRC3DIR NTLM_AUTH CCACHE SERVER
EOF
exit 1;
fi

PYTHON=$1
SRC3DIR=$2
NTLM_AUTH=$3
CCACHE=$4
SERVER=$5
shift 5
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

KRB5CCNAME=$CCACHE
export KRB5CCNAME

# --server-use-winbindd is set so we know it isn't cheating and using the hard-coded passwords

testit "ntlm_auth with krb5 gss-spnego-client and gss-spnego server" $PYTHON $SRC3DIR/torture/test_ntlm_auth.py $NTLM_AUTH $ADDARGS --target-hostname=$SERVER --target-service=host --client-helper=gss-spnego-client --server-helper=gss-spnego --server-use-winbindd || failed=`expr $failed + 1`


testok $0 $failed
