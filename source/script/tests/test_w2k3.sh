#!/bin/sh

# tests that should pass against a w2k3 DC, as administrator

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests="RPC-DSSETUP RPC-EPMAPPER RPC-SAMR RPC-WKSSVC RPC-SRVSVC RPC-EVENTLOG RPC-NETLOGON RPC-LSA"
ncacn_ip_tcp_tests="RPC-EPMAPPER RPC-SAMR RPC-LSA RPC-NETLOGON"

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_w2k3.sh SERVER USERNAME PASSWORD DOMAIN
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

for transport in ncacn_ip_tcp ncacn_np; do
 for bindoptions in connect sign seal validate bigendian; do
     case $transport in
	 ncacn_np) tests=$ncacn_np_tests ;;
	 ncacn_ip_tcp) tests=$ncacn_ip_tcp_tests ;;
     esac
   for t in $tests; do
    echo Testing $t on $transport with $bindoptions
    testit bin/smbtorture $transport:"$server[$bindoptions]" -U"$username"%"$password" -W $domain $t "$*"
   done
 done
done

echo Testing RPC-DRSUAPI on ncacn_ip_tcp with seal
testit bin/smbtorture ncacn_ip_tcp:"$server[seal]" -U"$username"%"$password" -W $domain RPC-DRSUAPI "$*"
echo Testing RPC-DRSUAPI on ncacn_ip_tcp with seal,bigendian
testit bin/smbtorture ncacn_ip_tcp:"$server[seal,bigendian]" -U"$username"%"$password" -W $domain RPC-DRSUAPI "$*"

echo "ALL OK";
