#!/bin/sh

if [ $# -lt 2 ]; then
cat <<EOF
Usage: $0 SERVER REALM
EOF
exit 1;
fi

SERVER=$1
REALM=$2
shift 2

failed=0
. `dirname $0`/subunit.sh

samba_net="$BINDIR/net"

DN=$(echo "${REALM}" | tr '[:upper:]' '[:lower:]' | sed -e 's!^!DC=!' -e 's!\.!,DC=!g')
testit_grep_count \
	"net_ads_search.ntlmssp" \
	"distinguishedName: ${DN}" \
	1 \
	$samba_net ads search --use-kerberos=off -P \
	--server "${SERVER}.${REALM}" \
	'(objectClass=domain)' distinguishedName || \
	failed=$((failed + 1))
testit_grep_count \
	"net_ads_search.krb5" \
	"distinguishedName: ${DN}" \
	1 \
	$samba_net ads search --use-kerberos=required -P \
	--server "${SERVER}.${REALM}" \
	'(objectClass=domain)' distinguishedName || \
	failed=$((failed + 1))

exit $failed
