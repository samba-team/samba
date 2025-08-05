#!/bin/bash

# Disabling history expansion temporarily
# This is needed, as the tdb key can include e.g. !6
set +H

WBINFO="$VALGRIND ${WBINFO:-$BINDIR/wbinfo}"
samba_tdbtool=tdbtool
if test -x $BINDIR/tdbtool; then
	samba_tdbtool=$BINDIR/tdbtool
fi
TDBTOOL="${TDBTOOL:-$samba_tdbtool}"

samba_tdbdump=tdbdump
if test -x $BINDIR/tdbdump; then
	samba_tdbdump=$BINDIR/tdbdump
fi
TDBDUMP="${TDBDUMP:-$samba_tdbdump}"

NET="$VALGRIND ${NET:-$BINDIR/net}"

cache="$LOCK_DIR"/winbindd_cache.tdb

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

testit "flush" "$NET" "cache" "flush" || failed=$(expr $failed + 1)
testit "lookuprids1" "$WBINFO" "-R" "512,12345" || failed=$(expr $failed + 1)

opnum=$($PYTHON -c'from samba.dcerpc.winbind import wbint_LookupRids; print(wbint_LookupRids.opnum())')
key=$("$TDBDUMP" "$cache" | awk -F'"' -v opnum="${opnum}" '/key.*NDR/ { regex = "NDR/[^/]+/" opnum "/.*$"; if (match($2, regex)) print substr($2, RSTART, RLENGTH) }')

testit "delete key" "$TDBTOOL" "$cache" delete "$key" || failed=$((failed + 1))
testit "lookuprids2" "$WBINFO" "-R" "512,12345" || failed=$(expr $failed + 1)

testok $0 $failed
