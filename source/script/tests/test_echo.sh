#!/bin/sh

incdir=`dirname $0`
. $incdir/test_functions.sh

transports="ncacn_np ncacn_ip_tcp ncalrpc"

for transport in $transports; do
 for bindoptions in connect spnego spnego,sign spnego,seal $VALIDATE padcheck bigendian bigendian,seal; do
  for ntlmoptions in \
        "--option=socket:testnonblock=True --option=torture:quick=yes"; do
   name="RPC-ECHO on $transport with $bindoptions and $ntlmoptions"
   plantest "$name" dc bin/smbtorture $TORTURE_OPTIONS $transport:"\$SERVER[$bindoptions]" $ntlmoptions -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" RPC-ECHO "$*"
  done
 done
done

for transport in $transports; do
 for bindoptions in sign seal; do
  for ntlmoptions in \
        "--option=ntlmssp_client:ntlm2=yes --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=no  --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=yes --option=ntlmssp_client:128bit=no --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=no  --option=ntlmssp_client:128bit=no --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=yes --option=ntlmssp_client:keyexchange=no --option=torture:quick=yes" \
        "--option=ntlmssp_client:ntlm2=no  --option=ntlmssp_client:keyexchange=no  --option=torture:quick=yes" \
        "--option=clientntlmv2auth=yes  --option=ntlmssp_client:keyexchange=no  --option=torture:quick=yes" \
        "--option=clientntlmv2auth=yes  --option=ntlmssp_client:128bit=no --option=ntlmssp_client:keyexchange=yes  --option=torture:quick=yes" \
        "--option=clientntlmv2auth=yes  --option=ntlmssp_client:128bit=no --option=ntlmssp_client:keyexchange=no  --option=torture:quick=yes" \
    ; do
   name="RPC-ECHO on $transport with $bindoptions and $ntlmoptions"
   plantest "$name" dc bin/smbtorture $TORTURE_OPTIONS $transport:"\$SERVER[$bindoptions]" $ntlmoptions -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN RPC-ECHO "$*"
  done
 done
done

name="RPC-ECHO on ncacn_np over smb2"
plantest "$name" dc bin/smbtorture $TORTURE_OPTIONS ncacn_np:"\$SERVER[smb2]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN RPC-ECHO "$*"
