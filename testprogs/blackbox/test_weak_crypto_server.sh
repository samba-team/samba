#!/bin/sh

#
# Blackbox tests for weak crytpo
# Copyright (c) 2020      Andreas Schneider <asn@samba.org>
#

if [ $# -lt 7 ]; then
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
CONFIGURATION=$7
shift 7

failed=0
. `dirname $0`/subunit.sh

samba_bindir="$BINDIR"
samba_testparm="$BINDIR/testparm"
samba_rpcclient="$samba_bindir/rpcclient"

# remove the --configfile=
configuration="${CONFIGURATION##*=}"

test_weak_crypto_allowed()
{
    local testparm_stderr_output_path="$PREFIX/testparm_stderr_output"

    $samba_testparm -s $configuration 2>$testparm_stderr_output_path >/dev/null

    grep "Weak crypto is allowed" $testparm_stderr_output_path >/dev/null 2>&1
    if [ $ret -ne 0 ]; then
        echo "Invalid crypto state:"
        cat $testparm_stderr_output_path
        rm -f $testparm_stderr_output_path
        return 1
    fi

    rm -f $testparm_stderr_output_path

    return 0
}

unset GNUTLS_FORCE_FIPS_MODE

# Checks that testparm reports: Weak crypto is disallowed
testit "testparm-weak-crypto" test_weak_crypto_allowed || failed=`expr $failed + 1`

# We should not be allowed to use NTLM for connecting
testit_expect_failure "rpclient.ntlm" $samba_rpcclient ncacn_np:$SERVER_IP[ntlm] -U$USERNAME%$PASSWORD -c "getusername" && failed=`expr $failed + 1`

GNUTLS_FORCE_FIPS_MODE=1
export GNUTLS_FORCE_FIPS_MODE

exit $failed
