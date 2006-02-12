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
for bindoptions in validate seal; do
 for keyexchange in "yes" "no"; do
 for ntlm2 in "yes" "no"; do
 for lm_key in "yes" "no"; do
  for ntlmoptions in \
        "-k no --option=usespnego=yes" \
        "-k no --option=usespnego=yes --option=ntlmssp_client:128bit=no" \
        "-k no --option=usespnego=yes --option=ntlmssp_client:56bit=yes" \
        "-k no --option=usespnego=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=yes" \
        "-k no --option=usespnego=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=no" \
        "-k no --option=usespnego=yes --option=clientntlmv2auth=yes" \
        "-k no --option=usespnego=yes --option=clientntlmv2auth=yes --option=ntlmssp_client:128bit=no" \
        "-k no --option=usespnego=yes --option=clientntlmv2auth=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=yes" \
        "-k no --option=usespnego=no --option=clientntlmv2auth=yes" \
        "-k no --option=usespnego=no" \
    ; do
   name="RPC-SECRETS on $transport:$server[$bindoptions] with NTLM2:$ntlm2 KEYEX:$keyexchange LM_KEY:$lm_key $ntlmoptions"
   testit "$name" bin/smbtorture $TORTURE_OPTIONS $transport:"$server[$bindoptions]" --option=ntlmssp_client:keyexchange=$keyexchange --option=ntlmssp_client:ntlm2=$ntlm2 --option=ntlmssp_client:lm_key=$lm_key $ntlmoptions -U"$username"%"$password" -W $domain RPC-SECRETS "$*" || failed=`expr $failed + 1`
  done
 done
 done
 done
done
testok $0 $failed
