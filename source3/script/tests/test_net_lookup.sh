#!/bin/sh

if [ $# != 6 ]; then
	echo "Usage: $0 SERVER USERNAME PASSWORD NET SAMBA-TOOL DNS-ZONE"
	exit 1
fi

SERVER="$1"
shift 1
USERNAME="$1"
shift 1
PASSWORD="$1"
shift 1
NET="$1"
shift 1
SAMBATOOL="$1"
shift 1
DNSZONE="$1"
shift 1

SITE="mysite"

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

$SAMBATOOL dns add "$SERVER" -U "$USERNAME"%"$PASSWORD" \
	_msdcs."$DNSZONE" _ldap._tcp."$SITE"._sites.dc \
	SRV "mydc.$DNSZONE 389 100 100"
$SAMBATOOL dns add "$SERVER" -U "$USERNAME"%"$PASSWORD" \
	"$DNSZONE" mydc \
	A "1.2.3.4"

# global lookup
testit_grep global 10.53.57.30:389 $NET lookup ldap "$DNSZONE" ||
	failed=$(expr $failed + 1)

# correct site-aware lookup
testit_grep site-aware 1.2.3.4:389 $NET lookup ldap "$DNSZONE" "$SITE" ||
	failed=$(expr $failed + 1)

# lookup with nonexisting site -- global fallback
testit_grep global 10.53.57.30:389 $NET lookup ldap "$DNSZONE" nosite ||
	failed=$(expr $failed + 1)

$SAMBATOOL dns delete "$SERVER" -U "$USERNAME"%"$PASSWORD" \
	"$DNSZONE" mydc \
	A "1.2.3.4"
$SAMBATOOL dns delete "$SERVER" -U "$USERNAME"%"$PASSWORD" \
	_msdcs."$DNSZONE" _ldap._tcp."$SITE"._sites.dc \
	SRV "mydc.$DNSZONE 389 100 100"

testok $0 $failed
