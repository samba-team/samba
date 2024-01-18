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
	      $wbinfo -m --verbose | grep "SAMBA-TEST" && return 0
	      sleep 2
	      i=$((i + 1))
    done
    return 1
}

testit "nt4trust_wbinfo_m" test_trust_wbinfo_m || failed=$(expr $failed + 1)

testok $0 $failed
