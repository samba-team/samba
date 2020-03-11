#!/bin/sh

#
# Blackbox tests for weak crytpo
# Copyright (c) 2020      Andreas Schneider <asn@samba.org>
#

if [ $# -lt 6 ]; then
cat <<EOF
Usage: $0 SERVER USERNAME PASSWORD REALM DOMAIN PREFIX
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
REALM=$4
DOMAIN=$5
PREFIX=$6
shift 6

failed=0
. `dirname $0`/subunit.sh

samba_bindir="$BINDIR"
samba_testparm="$BINDIR/testparm"
samba_rpcclient="$samba_bindir/rpcclient"

GNUTLS_FORCE_FIPS_MODE=1
export GNUTLS_FORCE_FIPS_MODE

# Checks that testparm reports: Weak crypto is disallowed
testit_grep "testparm" "Weak crypto is disallowed" $samba_testparm -s $SMB_CONF_PATH 2>&1 || failed=`expr $failed + 1`

# We should not be allowed to use NTLM for connecting
testit_expect_failure "rpclient.ntlm" $samba_rpcclient ncacn_np:$SERVER -U$USERNAME%$PASSWORD -c "getusername" || failed=`expr $failed + 1`

unset GNUTLS_FORCE_FIPS_MODE

exit $failed
