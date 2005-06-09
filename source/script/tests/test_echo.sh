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

failed=0
for transport in $transports; do
 for bindoptions in connect sign seal sign,seal validate padcheck bigendian bigendian,seal; do
  for ntlmoptions in \
        "--option=socket:testnonblock=True" \
        "--option=ntlmssp_client:ntlm2=yes" \
        "--option=ntlmssp_client:ntlm2=no  --option=torture:echo_TestSleep=no" \
        "--option=ntlmssp_client:ntlm2=yes --option=ntlmssp_client:128bit=no" \
        "--option=ntlmssp_client:ntlm2=no  --option=ntlmssp_client:128bit=no       --option=torture:echo_TestSleep=no" \
        "--option=ntlmssp_client:ntlm2=yes --option=ntlmssp_client:keyexchange=no" \
        "--option=ntlmssp_client:ntlm2=no  --option=ntlmssp_client:keyexchange=no  --option=torture:echo_TestSleep=no" \
    ; do
   name="$transport with $bindoptions and $ntlmoptions"
   testit "$name" bin/smbtorture $transport:"$server[$bindoptions]" $ntlmoptions -U"$username"%"$password" -W $domain RPC-ECHO "$*" || failed=`expr $failed + 1`
  done
 done
done

# separately test the print option - its v slow
name="print option"
testit bin/smbtorture "$name" ncacn_np:"$server[print]" -U"$username"%"$password" -W $domain RPC-ECHO "$*" || failed=`expr $failed + 1`

testok $0 $failed
