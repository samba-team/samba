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
       exit 1;
   fi
   rm -f test.$$;
}

for I in "ncacn_np:$server" \
		 "ncacn_ip_tcp:$server" \
		 "ncacn_np:$server[rpcecho]"  \
		 "ncacn_np:$server[/pipe/rpcecho]" \
		 "ncacn_np:$server[/pipe/rpcecho,sign,seal]" \
		 "ncacn_np:$server[,sign]" \
		 "ncacn_ip_tcp:$server[,sign]" \
		 "308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_np:$server" \
		 "308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_ip_tcp:$server" 
do
	testit bin/smbtorture "$I" -U"$username"%"$password" -W $domain RPC-ECHO "$*"
done

echo "ALL OK";
