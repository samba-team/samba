#!/bin/sh

# add tests to this list as they start passing, so we test
# that they stay passing
tests="RPC-SCHANNEL RPC-ECHO"

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

testit() {
   cmdline="$*"
   if ! $cmdline > test.$$ 2>&1; then
       cat test.$$;
       rm -f test.$$;
       echo "TEST FAILED - $cmdline";
       exit 1;
   fi
   rm -f test.$$;
}

for transport in ncalrpc ncacn_np ncacn_ip_tcp; do
 for bindoptions in connect sign seal sign,seal validate padcheck bigendian bigendian,seal; do
   for t in $tests; do
    echo Testing $t on $transport with $bindoptions
    testit bin/smbtorture $transport:"$server[$bindoptions]" -U"$username"%"$password" -W $domain $t "$*"
   done
 done
done

echo "ALL OK";
