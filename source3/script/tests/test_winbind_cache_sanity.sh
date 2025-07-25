#!/bin/sh

if [ $# -lt 2 ]; then
	cat <<EOF
Usage: test_winbind_cache_sanity.sh DOMAIN CACHE
EOF
	exit 1
fi

DOMAIN="$1"
CACHE="$2"
shift 2
ADDARGS="$*"

TDBTOOL=tdbtool
if test -x "$BINDIR"/tdbtool; then
	TDBTOOL=$BINDIR/tdbtool
fi
DBWRAP_TOOL=$BINDIR/dbwrap_tool
WBINFO=$BINDIR/wbinfo

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir"/subunit.sh


#################################################
## Test "$CACHE" presence
#################################################

testit "$CACHE presence" \
	test -r "$CACHE" \
	|| failed=$((failed + 1))


#################################################
## Test very simple wbinfo query to fill up cache with NDR/ and SEQNUM/ entries
#################################################

separator=$("$WBINFO" --separator)

testit "calling wbinfo -n$DOMAIN$separator to fillup cache" \
	"$VALGRIND" "$WBINFO" -n "$DOMAIN$separator" \
	"$ADDARGS" \
	|| failed=$((failed + 1))


#################################################
## Test "WINBINDD_CACHE_VERSION" presence
#################################################

KEY="WINBINDD_CACHE_VERSION"
WINBINDD_CACHE_VER2=2

testit "$KEY presence via dbwrap" \
	"$VALGRIND" "$DBWRAP_TOOL" --persistent "$CACHE" fetch $KEY uint32 \
	"$ADDARGS" \
	|| failed=$((failed + 1))

#tdbtool will never fail so we have to parse the output...
testit_grep "$KEY presence via tdbtool" "data 4 bytes" \
	"$VALGRIND" "$TDBTOOL" "$CACHE" show "$KEY\\00" \
	"$ADDARGS" \
	|| failed=$((failed + 1))

current_ver=$("$DBWRAP_TOOL" --persistent "$CACHE" fetch $KEY uint32)

testit "$KEY value via dbwrap to be WINBINDD_CACHE_VER2" \
	test "$current_ver" = $WINBINDD_CACHE_VER2 \
	|| failed=$((failed + 1))


#################################################
## Test "SEQNUM/$DOMAIN" presence
#################################################

KEY="SEQNUM/$DOMAIN"

testit "$KEY SEQNUM presence via dbwrap" \
	"$VALGRIND" "$DBWRAP_TOOL" --persistent "$CACHE" exists "$KEY" \
	"$ADDARGS" \
	|| failed=$((failed + 1))

#tdbtool will never fail so we have to parse the output...
testit_grep "$KEY SEQNUM presence via tdbtool" "data 8 bytes" \
	"$VALGRIND" "$TDBTOOL" "$CACHE" show "$KEY\\00" \
	"$ADDARGS" \
	|| failed=$((failed + 1))


#################################################
## Test "NDR/$DOMAIN/3/\09\00\00\00\00\00\00\00\09\00\00\00$DOMAIN\00\00\00\00\01\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00" presence
## this is the resulting cache entry for a simple
## wbinfo -n $DOMAIN\ query
#################################################

opnum=$($PYTHON -c'from samba.dcerpc.winbind import wbint_LookupName; print(wbint_LookupName.opnum())')
KEY="NDR/$DOMAIN/$opnum/\\09\\00\\00\\00\\00\\00\\00\\00\\09\\00\\00\\00$DOMAIN\\00\\00\\00\\00\\01\\00\\00\\00\\00\\00\\00\\00\\01\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00"

#DBWRAP_TOOL does not support non-null terminated keys so it cannot find it...
#testit "$KEY NDR presence via dbwrap" \
#	"$VALGRIND" "$DBWRAP_TOOL" --persistent $CACHE exists $KEY \
#	"$ADDARGS" \
#	|| failed=$((failed + 1))

#tdbtool will never fail so we have to parse the output...
# key 59 bytes
testit_grep "$KEY NDR presence via tdbtool" "data 44 bytes" \
	"$VALGRIND" "$TDBTOOL" "$CACHE" show "$KEY" \
	"$ADDARGS" \
	|| failed=$((failed + 1))

testok "$0" "$failed"
