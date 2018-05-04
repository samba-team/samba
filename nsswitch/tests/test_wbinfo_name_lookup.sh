#!/bin/sh
# Blackbox test for wbinfo name lookup
if [ $# -lt 2 ]; then
cat <<EOF
Usage: test_wbinfo.sh DOMAIN DC_USERNAME
EOF
exit 1;
fi

DOMAIN=$1
REALM=$2
DC_USERNAME=$3
shift 3

failed=0
sambabindir="$BINDIR"
wbinfo="$VALGRIND $sambabindir/wbinfo"

. `dirname $0`/../../testprogs/blackbox/subunit.sh

# Correct query is expected to work
testit "name-to-sid.single-separator" \
       $wbinfo -n $DOMAIN/$DC_USERNAME || \
	failed=$(expr $failed + 1)

testit "name-to-sid.at_domain" \
       $wbinfo -n $DOMAIN/ || \
	failed=$(expr $failed + 1)

testit "name-to-sid.upn" \
       $wbinfo -n $DC_USERNAME@$REALM || \
	failed=$(expr $failed + 1)

# Two separator characters should fail
testit_expect_failure "name-to-sid.double-separator" \
		      $wbinfo -n $DOMAIN//$DC_USERNAME || \
	failed=$(expr $failed + 1)

# Invalid domain is expected to fail
testit_expect_failure "name-to-sid.invalid-domain" \
		      $wbinfo -n INVALID/$DC_USERNAME || \
	failed=$(expr $failed + 1)

# Invalid domain with two separator characters is expected to fail
testit_expect_failure "name-to-sid.double-separator-invalid-domain" \
		      $wbinfo -n INVALID//$DC_USERNAME || \
	failed=$(expr $failed + 1)

exit $failed
