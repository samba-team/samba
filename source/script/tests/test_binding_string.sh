#!/bin/sh

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_binding_string.sh SERVER USERNAME PASSWORD DOMAIN
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

failed=0;
for I in "ncacn_np:$server" \
		 "ncacn_ip_tcp:$server" \
		 "ncacn_np:$server[rpcecho]"  \
		 "ncacn_np:$server[/pipe/rpcecho]" \
		 "ncacn_np:$server[/pipe/rpcecho,sign,seal]" \
		 "ncacn_np:$server[,sign]" \
		 "ncacn_ip_tcp:$server[,sign]" \
		 "ncalrpc:" \
		 "308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_np:$server" \
		 "308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_ip_tcp:$server" 
do
	echo Testing $I
	testit bin/smbtorture "$I" -U"$username"%"$password" -W $domain RPC-ECHO "$*" || failed=`expr $failed + 1`
done

testok $0 $failed
