#!/bin/sh

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests="RPC-SCHANNEL RPC-ECHO RPC-DSSETUP RPC-SAMLOGON RPC-ALTERCONTEXT RPC-MULTIBIND"
ncalrpc_tests="RPC-SCHANNEL RPC-ECHO RPC-DSSETUP RPC-SAMLOGON RPC-ALTERCONTEXT RPC-MULTIBIND"
ncacn_ip_tcp_tests="RPC-SCHANNEL RPC-ECHO RPC-DSSETUP RPC-SAMLOGON RPC-ALTERCONTEXT RPC-MULTIBIND"

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_rpc.sh SERVER USERNAME PASSWORD DOMAIN
EOF
exit 1;
fi

if [ -z "$VALGRIND" ]; then
    export MALLOC_CHECK_=2
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
       return 1;
   fi
   rm -f test.$$;
   return 0;
}

testok() {
    name=`basename $1`
    failed=$2
    if [ x"$failed" = x"0" ];then
	echo "ALL OK ($name)";
    else
	echo "$failed TESTS FAILED ($name)";
    fi
    exit $failed
}

failed=0
for bindoptions in connect sign seal sign,seal spnego spnego,sign spnego,seal validate padcheck bigendian bigendian,seal; do
 for transport in ncalrpc ncacn_np ncacn_ip_tcp; do
     case $transport in
	 ncalrpc) tests=$ncalrpc_tests ;;
	 ncacn_np) tests=$ncacn_np_tests ;;
	 ncacn_ip_tcp) tests=$ncacn_ip_tcp_tests ;;
     esac
   for t in $tests; do
    echo Testing $t on $transport with $bindoptions
    testit $VALGRIND bin/smbtorture $transport:"$server[$bindoptions]" -U"$username"%"$password" -W $domain $t "$*" || failed=`expr $failed + 1`
   done
 done
done

testok $0 $failed
