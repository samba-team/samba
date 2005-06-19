#!/bin/sh

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_session_key.sh SERVER USERNAME PASSWORD DOMAIN
EOF
exit 1;
fi

server="$1"
username="$2"
password="$3"
domain="$4"
shift 4

incdir=`dirname $0`
. $incdir/test_functions.sh

failed=0
transport="ncacn_np"
  for ntlmoptions in \
        "--option=usespnego=yes --option=ntlmssp_client:ntlm2=yes" \
        "--option=usespnego=yes --option=ntlmssp_client:ntlm2=no" \
        "--option=usespnego=yes --option=ntlmssp_client:ntlm2=yes --option=ntlmssp_client:128bit=no" \
        "--option=usespnego=yes--option=ntlmssp_client:ntlm2=no  --option=ntlmssp_client:128bit=no" \
        "--option=usespnego=yes --option=ntlmssp_client:ntlm2=yes --option=ntlmssp_client:keyexchange=no" \
        "--option=usespnego=yes --option=ntlmssp_client:ntlm2=no  --option=ntlmssp_client:keyexchange=no" \
        "--option=usespnego=yes --option=clientntlmv2auth=yes  --option=ntlmssp_client:keyexchange=no" \
        "--option=usespnego=yes --option=clientntlmv2auth=yes  --option=ntlmssp_client:keyexchange=yes" \
        "--option=usespnego=yes --option=clientntlmv2auth=yes  --option=ntlmssp_client:keyexchange=yes --option=ntlmssp_client:128bit=no" \
        "--option=usespnego=yes --option=clientntlmv2auth=yes  --option=ntlmssp_client:keyexchange=no --option=ntlmssp_client:128bit=no" \
        "--option=usespnego=no --option=clientntlmv2auth=yes" \
        "--option=usespnego=no" \
    ; do
   name="RPC-SECRETS on $transport with $ntlmoptions"
   testit "$name" bin/smbtorture $TORTURE_OPTIONS $transport:"$server[$bindoptions]" $ntlmoptions -U"$username"%"$password" -W $domain RPC-SECRETS "$*" || failed=`expr $failed + 1`
  done
testok $0 $failed
