#!/bin/sh
# Blackbox tests for net ads dns async
# Copyright (C) 2020 Jeremy Allison <jra@samba.org>

if [ $# -lt 2 ]; then
cat <<EOF
Usage: test_net_ads_dns_async.sh SERVER REALM
EOF
exit 1;
fi

SERVER=$1
REALM=$2
shift 2
failed=0

samba4bindir="$BINDIR"
net_tool="$samba4bindir/net"

. `dirname $0`/subunit.sh

# Test looking up SERVER.REALM on server give the
# same IP via async and non-async DNS.
echo "Starting ..."

test_async_dns() {
	#
	# Do the gethostbyname request. This just prints the IPv4 addr.
	#
	cmd_sync='$net_tool ads dns gethostbyname $SERVER $SERVER.$REALM'
	eval echo "$cmd_sync"
	ipv4_sync=$(eval $cmd_sync)
	if [ -z "$ipv4_sync" ]; then
		return 1
	fi

	#
	# Do the async request. This prints out info like:
	#
	# Async A record lookup - got 1 names for addc.ADDOM.SAMBA.EXAMPLE.COM
	# hostname[0] = addc.ADDOM.SAMBA.EXAMPLE.COM, IPv4addr = 10.53.57.30
	# Async AAAA record lookup - got 1 names for addc.ADDOM.SAMBA.EXAMPLE.COM
	# hostname[0] = addc.ADDOM.SAMBA.EXAMPLE.COM, IPv6addr = fd00::5357:5f1e
	#
	# So we must grep and sed to extract the matching IPv4 address
	#
	cmd_async='$net_tool ads dns async $SERVER.$REALM'
	eval echo "$cmd_async"
	out_async=$(eval $cmd_async)

	# Drop everything but the IPv4 address.
	ipv4_async=`echo "$out_async" | grep IPv4addr | sed -e 's/^.*IPv4addr = //'`

	if [ -z "$ipv4_async" ]; then
		return 1
	fi
	if [ "$ipv4_sync" != "$ipv4_async" ]; then
		echo "DNS lookup mismatch. Sync $ipv4_sync, async $ipv4_async"
		echo "DNS commands output. out1=$ipv4_sync, out2=$out_async"
		return 1
	fi
	return 0
}

testit "Check async and non async DNS lookups match " test_async_dns || failed=`expr $failed + 1`

exit $failed
