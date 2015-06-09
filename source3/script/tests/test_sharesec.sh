#!/bin/sh
#
# Test sharesec command.
#
# Verify that changing and querying the security descriptor works. Also
# ensure that the output format for ACL entries does not change.
#
# The test uses well-known SIDs to not require looking up names and SIDs
#
# Copyright (C) 2015 Christof Schmitt

if [ $# -lt 3 ]; then
Usage: test_sharesec.sh SERVERCONFFILE SHARESEC SHARE
exit 1
fi

CONF=$1
SHARESEC=$2
SHARE=$3

CMD="$SHARESEC $CONF $SHARE"

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

testit "Set new ACL" $CMD --replace  S-1-1-0:ALLOWED/0x0/READ || \
	failed=$(expr $failed + 1)
testit "Query new ACL" $CMD --view || failed=$(expr $failed + 1)
COUNT=$($CMD --view | grep ACL: | sed -e 's/^ACL://' | wc -l)
testit "Verify new ACL count" test $COUNT -eq 1 || failed=$(expr $failed + 1)
ACL=$($CMD --view | grep ACL: | sed -e 's/^ACL://')
testit "Verify new ACL" test $ACL = S-1-1-0:ALLOWED/0x0/READ

OWNER=$($CMD --view | grep OWNER:)
testit "Verify empty OWNER" test "$OWNER" = "OWNER:" || \
	failed=$(expr $failed + 1)
GROUP=$($CMD --view | grep GROUP:)
testit "Verify empty GROUP" test "$GROUP" = "GROUP:" || \
	failed=$(expr $failed + 1)
CONTROL=$($CMD --view | grep CONTROL: | sed -e 's/^CONTROL://')
testit "Verify control flags" test "$CONTROL" = "SR|DP" || \
	failed=$(expr $failed + 1)

testit "Add second ACL entry" $CMD --add S-1-5-32-544:ALLOWED/0x0/FULL || \
	failed=$(expr $failed + 1)
testit "Query ACL with two entries" $CMD --view || \
	failed=$(expr $failed + 1)
COUNT=$($CMD --view | grep ACL: | sed -e 's/^ACL://' | wc -l)
testit "Verify ACL count with two entries" test $COUNT -eq 2 || \
	failed=$(expr $failed + 1)
ACL=$($CMD --view | grep S-1-5-32-544 | sed -e 's/^ACL://')
testit "Verify second ACL entry" test $ACL = S-1-5-32-544:ALLOWED/0x0/FULL || \
	failed=$(expr $failed + 1)

testit "Modify ACL entry" $CMD --modify S-1-5-32-544:ALLOWED/0x0/CHANGE || \
	failed=$(expr $failed + 1)
testit "Verify ACL with two entries after modify" $CMD --view || \
	failed=$(expr $failed + 1)
COUNT=$($CMD --view | grep ACL: | sed -e 's/^ACL://' | wc -l)
testit "Verify ACL count with two entries after modify" test $COUNT -eq 2 || \
	failed=$(expr $failed + 1)
ACL=$($CMD --view | grep S-1-5-32-544 | sed -e 's/^ACL://')
testit "Verify modified entry" test $ACL = S-1-5-32-544:ALLOWED/0x0/CHANGE || \
	failed=$(expr $failed + 1)

testit "Add deny ACL entry" $CMD --add S-1-5-32-545:DENIED/0x0/CHANGE || \
	failed=$(expr $failed + 1)
testit "Query ACL with three entries" $CMD --view || \
	failed=$(expr $failed + 1)
COUNT=$($CMD --view | grep ACL: | sed -e 's/^ACL://' | wc -l)
testit "Verify ACL count with three entries" test $COUNT -eq 3 || \
	failed=$(expr $failed + 1)
ACL=$($CMD --view | grep S-1-5-32-545 | sed -e 's/^ACL://')
testit "Verify DENIED ACL entry" test $ACL = S-1-5-32-545:DENIED/0x0/CHANGE || \
	failed=$(expr $failed + 1)

testit "Add special ACL entry" $CMD --add S-1-5-32-546:ALLOWED/0x0/RWXDP || \
	failed=$(expr $failed + 1)
testit "Query ACL with four entries" $CMD --view || \
	failed=$(expr $failed + 1)
COUNT=$($CMD --view | grep ACL: | sed -e 's/^ACL://' | wc -l)
testit "Verify ACL count with four entries" test $COUNT -eq 4 || \
	failed=$(expr $failed + 1)
ACL=$($CMD --view | grep S-1-5-32-546 | sed -e 's/^ACL://')
testit "Verify special entry" test $ACL = S-1-5-32-546:ALLOWED/0x0/RWXDP || \
	failed=$(expr $failed + 1)

testit "Remove ACL entry" $CMD --remove S-1-5-32-546:ALLOWED/0x0/RWXDP || \
	failed=$(expr $failed + 1)
testit "Query ACL with three entries after removal" $CMD --view || \
	failed=$(expr $failed + 1)
COUNT=$($CMD --view | grep ACL: | sed -e 's/^ACL://' | wc -l)
testit "Verify ACL count after removal" test $COUNT -eq 3 || \
	failed=$(expr $failed + 1)
ACL="$($CMD --view | grep S-1-5-32-546')"
testit "Verify removal" test -e "$ACL" || failed=$(expr $failed + 1)

testit "Set back to default ACL " $CMD --replace  S-1-1-0:ALLOWED/0x0/FULL || \
	failed=$(expr $failed + 1)
testit "Query standard ACL" $CMD --view || \
	failed=$(expr $failed + 1)
COUNT=$($CMD --view | grep ACL: | sed -e 's/^ACL://' | wc -l)
testit "Verify standard ACL count" test $COUNT -eq 1 || \
	failed=$(expr $failed + 1)
ACL=$($CMD --view | grep ACL: | sed -e 's/^ACL://')
testit "Verify standard ACL" test $ACL = S-1-1-0:ALLOWED/0x0/FULL || \
	failed=$(expr $failed + 1)

testok $0 $failed
