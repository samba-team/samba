#!/bin/sh

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests="RPC-SCHANNEL RPC-ECHO RPC-DSSETUP"
ncalrpc_tests="RPC-SCHANNEL RPC-ECHO RPC-DSSETUP"
ncacn_ip_tcp_tests="RPC-SCHANNEL RPC-ECHO"

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
   trap "rm -f test.$$" EXIT
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
     case $transport in
	 ncalrpc) tests=$ncalrpc_tests ;;
	 ncacn_np) tests=$ncacn_np_tests ;;
	 ncacn_ip_tcp) tests=$ncacn_ip_tcp_tests ;;
     esac
   for t in $tests; do
    echo Testing $t on $transport with $bindoptions
    testit bin/smbtorture $transport:"$server[$bindoptions]" -U"$username"%"$password" -W $domain $t "$*"
   done
 done
done

echo "ALL OK";
