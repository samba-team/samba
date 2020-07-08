#!/bin/sh

WBINFO="$VALGRIND ${WBINFO:-$BINDIR/wbinfo}"
TDBTOOL="${TDBTOOL:-$BINDIR/tdbtool}"
TDBDUMP="${TDBDUMP:-$BINDIR/tdbdump}"
NET="$VALGRIND ${NET:-$BINDIR/net}"

cache="$LOCK_DIR"/winbindd_cache.tdb

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

testit "flush" "$NET" "cache" "flush" || failed=`expr $failed + 1`
testit "lookuprids1" "$WBINFO" "-R" "512,12345" || failed=`expr $failed + 1`

key=$("$TDBDUMP" "$cache" | grep ^key.*NDR.*/16/ | cut -d\" -f2)

testit "delete" "$TDBTOOL" "$cache" delete "$key"
testit "lookuprids2" "$WBINFO" "-R" "512,12345" || failed=`expr $failed + 1`

testok $0 $failed
