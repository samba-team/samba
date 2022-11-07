#!/bin/sh
#
# Blackbox test for the server addresses parameter
#

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

testit_grep_count \
    "[only_ipv6] invisible over ipv4" "netname: only_ipv6" 0 \
    bin/rpcclient "$SERVER_IP" -U% -c netshareenumall ||
    failed=$(expr "$failed" + 1)

testit_grep_count \
    "[only_ipv6] visible over ipv6" "netname: only_ipv6" 1 \
    bin/rpcclient "$SERVER_IPV6" -U% -c netshareenumall ||
    failed=$(expr "$failed" + 1)

testit_expect_failure_grep \
    "[only_ipv6] inaccessible over ipv4" \
    "tree connect failed: NT_STATUS_BAD_NETWORK_NAME" \
    bin/smbclient //"$SERVER_IP"/only_ipv6 -U% -c quit ||
    failed=$(expr "$failed" + 1)

testit \
    "[only_ipv6] accessible over ipv6" \
    bin/smbclient //"$SERVER_IPV6"/only_ipv6 -U% -c quit ||
    failed=$(expr "$failed" + 1)

testok $0 $failed
