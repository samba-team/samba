#!/bin/sh

# tests that should pass against a w2k3 DC, as administrator

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests="RPC-SCHANNEL RPC-DSSETUP RPC-EPMAPPER RPC-SAMR RPC-WKSSVC RPC-SRVSVC RPC-EVENTLOG RPC-NETLOGON RPC-LSA RPC-SAMLOGON RPC-SAMSYNC RPC-MULTIBIND RPC-WINREG"
ncacn_ip_tcp_tests="RPC-SCHANNEL RPC-EPMAPPER RPC-SAMR RPC-NETLOGON RPC-LSA RPC-SAMLOGON RPC-SAMSYNC RPC-MULTIBIND"

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_w2k3.sh SERVER USERNAME PASSWORD DOMAIN REALM
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
realm="$5"
shift 5

testit() {
   trap "rm -f test.$$" EXIT
   cmdline="$*"
   if ! $VALGRIND $cmdline > test.$$ 2>&1; then
       cat test.$$;
       rm -f test.$$;
       echo "TEST FAILED - $cmdline";
       exit 1;
   fi
   rm -f test.$$;
}

OPTIONS="-U$username%$password -W $domain --option realm=$realm"

echo Testing RPC-SPOOLSS on ncacn_np
testit bin/smbtorture ncacn_np:"$server" $OPTIONS RPC-SPOOLSS "$*"

for bindoptions in padcheck connect sign seal spnego,sign spnego,seal validate bigendian; do
   for transport in ncacn_ip_tcp ncacn_np; do
     case $transport in
	 ncacn_np) tests=$ncacn_np_tests ;;
	 ncacn_ip_tcp) tests=$ncacn_ip_tcp_tests ;;
     esac
   for t in $tests; do
    echo Testing $t on $transport with $bindoptions
    testit bin/smbtorture $transport:"$server[$bindoptions]" $OPTIONS $t "$*"
   done
 done
done

echo Testing RPC-DRSUAPI on ncacn_ip_tcp with seal
testit bin/smbtorture ncacn_ip_tcp:"$server[seal]" $OPTIONS RPC-DRSUAPI "$*"
echo Testing RPC-DRSUAPI on ncacn_ip_tcp with seal,bigendian
testit bin/smbtorture ncacn_ip_tcp:"$server[seal,bigendian]" $OPTIONS RPC-DRSUAPI "$*"

echo "ALL OK";
