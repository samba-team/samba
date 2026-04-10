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

ndr_keys=$("$TDBDUMP" "$cache" | awk -F'"' -v opnum="${opnum}" '/key.*NDR/ { regex = "NDR/[^/]+/" opnum "/.*$"; if (match($2, regex)) print substr($2, RSTART, RLENGTH) }')
ndr_key_count=$(echo "$ndr_keys" | grep -c .)
echo "DEBUG: Found ${ndr_key_count} NDR key(s) for opnum ${opnum}:"
echo "$ndr_keys" | while IFS= read -r k; do
	echo "  key='${k}' (length=${#k})"
done

key=$(echo "$ndr_keys" | head -1)
echo "DEBUG: Using key='${key}' (length=${#key})"

if [ -n "$key" ]; then
	echo "DEBUG: Verifying key exists with tdbtool show..."
	"$TDBTOOL" "$cache" show "$key" 2>&1 \
		&& echo "DEBUG: Key found in TDB" \
		|| echo "DEBUG: Key NOT found in TDB (show failed)"
fi

testit "delete key" "$TDBTOOL" "$cache" delete "$key" || {
	failed=$((failed + 1))
	echo "DEBUG: Post-failure TDB dump of NDR keys:"
	"$TDBDUMP" "$cache" | grep -A1 "key.*NDR"
}
testit "lookuprids2" "$WBINFO" "-R" "512,12345" || failed=$(expr $failed + 1)

testok $0 $failed
