#!/bin/sh

incdir=`dirname $0`
. $incdir/test_functions.sh

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
   plantest "$name" dc bin/smbtorture $TORTURE_OPTIONS $transport:"\$SERVER[$bindoptions]" --option=ntlmssp_client:keyexchange=$keyexchange --option=ntlmssp_client:ntlm2=$ntlm2 --option=ntlmssp_client:lm_key=$lm_key $ntlmoptions -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN --option=gensec:target_hostname=\$NETBIOSNAME RPC-SECRETS "$*"
  done
 done
 done
 done
 name="RPC-SECRETS on $transport with $bindoptions with Kerberos"
 plantest "$name" dc bin/smbtorture $TORTURE_OPTIONS $transport:"\$SERVER[$bindoptions]" -k yes -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN "--option=gensec:target_hostname=\$NETBIOSNAME" RPC-SECRETS "$*"
 name="RPC-SECRETS on $transport with $bindoptions with Kerberos - use target principal"
 plantest "$name" dc bin/smbtorture $TORTURE_OPTIONS $transport:"\$SERVER[$bindoptions]" -k yes -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN "--option=clientusespnegoprincipal=yes" "--option=gensec:target_hostname=\$NETBIOSNAME" RPC-SECRETS "$*"
done
name="RPC-SECRETS on $transport with Kerberos - use Samba3 style login"
 plantest "$name" dc bin/smbtorture $TORTURE_OPTIONS $transport:"\$SERVER" -k yes -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" "--option=gensec:fake_gssapi_krb5=yes" "--option=gensec:gssapi_krb5=no" "--option=gensec:target_hostname=\$NETBIOSNAME" RPC-SECRETS "$*"
name="RPC-SECRETS on $transport with Kerberos - use Samba3 style login, use target principal"
 plantest "$name" dc bin/smbtorture $TORTURE_OPTIONS $transport:"\$SERVER" -k yes -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" "--option=clientusespnegoprincipal=yes" "--option=gensec:fake_gssapi_krb5=yes" "--option=gensec:gssapi_krb5=no" "--option=gensec:target_hostname=\$NETBIOSNAME" RPC-SECRETS "$*"
