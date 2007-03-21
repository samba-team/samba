#!/bin/sh

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_echo.sh SERVER USERNAME PASSWORD DOMAIN
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

transports="ncacn_np ncacn_ip_tcp"
if [ $server = "localhost" ]; then 
    transports="ncalrpc $transports"
fi
if [ $server = "localtest" ]; then 
    transports="ncalrpc $transports"
fi

failed=0
for transport in $transports; do
 for bindoptions in connect spnego spnego,sign spnego,seal $VALIDATE padcheck bigendian bigendian,seal; do
  for ntlmoptions in \
        "--option=socket:testnonblock=True --option=torture:quick=yes"; do
   name="RPC-ECHO on $transport with $bindoptions and $ntlmoptions"
   testit "$name" rpc bin/smbtorture $TORTURE_OPTIONS $transport:"$server[$bindoptions]" $ntlmoptions -U"$username"%"$password" -W $domain RPC-ECHO "$*"
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
   testit "$name" rpc bin/smbtorture $TORTURE_OPTIONS $transport:"$server[$bindoptions]" $ntlmoptions -U"$username"%"$password" -W $domain RPC-ECHO "$*"
  done
 done
done

name="RPC-ECHO on ncacn_np over smb2"
testit "$name" rpc bin/smbtorture $TORTURE_OPTIONS ncacn_np:"$server[smb2]" -U"$username"%"$password" -W $domain RPC-ECHO "$*"

testok $0 $failed
