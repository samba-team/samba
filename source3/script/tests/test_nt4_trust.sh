#!/bin/sh

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh
. $incdir/common_test_fns.inc

failed=0

wbinfo="$BINDIR/wbinfo"
smbclient="$BINDIR/smbclient"

test_trust_wbinfo_m() {
    i=0
    # Give the server some time to list trusted domains
    while [ $i -lt 10 ] ; do
	      $wbinfo -m | grep SAMBA-TEST && return 0
	      sleep 2
	      i=$((i + 1))
    done
    return 1
}

test_trust_smbclient() {
    $smbclient //$NT4_TRUST_SERVER_IP/tmp -U "$DOMAIN/$DOMAIN_USER%$DOMAIN_USER_PASSWORD" -c quit || return 1
    return 0
}

testit "nt4trust_wbinfo_m" test_trust_wbinfo_m || failed=$(expr $failed + 1)
testit "nt4trust_smbclient" test_trust_smbclient || failed=$(expr $failed + 1)

testok $0 $failed
