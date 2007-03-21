#!/bin/sh

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_session_key.sh SERVER USERNAME PASSWORD DOMAIN NETBIOSNAME
EOF
exit 1;
fi

server="$1"
username="$2"
password="$3"
domain="$4"
netbios_name="$5"
shift 5

incdir=`dirname $0`
. $incdir/test_functions.sh

failed=0
transport="ncacn_np"
for bindoptions in bigendian seal; do
 for keyexchange in "yes" "no"; do
 for ntlm2 in "yes" "no"; do
 for lm_key in "yes" "no"; do
  for ntlmoptions in \
        "-k no --option=usespnego=yes" \
        "-k no --option=usespnego=yes --option=ntlmssp_client:128bit=no" \
        "-k no --option=usespnego=yes --option=ntlmssp_client:56bit=yes" \
        "-k no --option=usespnego=yes --option=ntlmssp_client:56bit=no" \
        "-k no --option=usespnego=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=yes" \
        "-k no --option=usespnego=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=no" \
        "-k no --option=usespnego=yes --option=clientntlmv2auth=yes" \
        "-k no --option=usespnego=yes --option=clientntlmv2auth=yes --option=ntlmssp_client:128bit=no" \
        "-k no --option=usespnego=yes --option=clientntlmv2auth=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=yes" \
        "-k no --option=usespnego=no --option=clientntlmv2auth=yes" \
        "-k no --option=gensec:spnego=no --option=clientntlmv2auth=yes" \
        "-k no --option=usespnego=no"; do
   name="RPC-SECRETS on $transport with $bindoptions with NTLM2:$ntlm2 KEYEX:$keyexchange LM_KEY:$lm_key $ntlmoptions"
   testit "$name" rpc bin/smbtorture $TORTURE_OPTIONS $transport:"$server[$bindoptions]" --option=ntlmssp_client:keyexchange=$keyexchange --option=ntlmssp_client:ntlm2=$ntlm2 --option=ntlmssp_client:lm_key=$lm_key $ntlmoptions -U"$username"%"$password" -W $domain --option=gensec:target_hostname=$netbios_name RPC-SECRETS "$*"
  done
 done
 done
 done
 name="RPC-SECRETS on $transport with $bindoptions with Kerberos"
 testit "$name" rpc bin/smbtorture $TORTURE_OPTIONS $transport:"$server[$bindoptions]" -k yes -U"$username"%"$password" -W $domain "--option=gensec:target_hostname=$netbios_name" RPC-SECRETS "$*"
 name="RPC-SECRETS on $transport with $bindoptions with Kerberos - use target principal"
 testit "$name" rpc bin/smbtorture $TORTURE_OPTIONS $transport:"$server[$bindoptions]" -k yes -U"$username"%"$password" -W $domain "--option=clientusespnegoprincipal=yes" "--option=gensec:target_hostname=$netbios_name" RPC-SECRETS "$*"
done
name="RPC-SECRETS on $transport with Kerberos - use Samba3 style login"
 testit "$name" rpc bin/smbtorture $TORTURE_OPTIONS $transport:"$server" -k yes -U"$username"%"$password" -W $domain "--option=gensec:fake_gssapi_krb5=yes" "--option=gensec:gssapi_krb5=no" "--option=gensec:target_hostname=$netbios_name" RPC-SECRETS "$*"
name="RPC-SECRETS on $transport with Kerberos - use Samba3 style login, use target principal"
 testit "$name" rpc bin/smbtorture $TORTURE_OPTIONS $transport:"$server" -k yes -U"$username"%"$password" -W $domain "--option=clientusespnegoprincipal=yes" "--option=gensec:fake_gssapi_krb5=yes" "--option=gensec:gssapi_krb5=no" "--option=gensec:target_hostname=$netbios_name" RPC-SECRETS "$*"
testok $0 $failed
