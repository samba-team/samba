#!/bin/sh

incdir=`dirname $0`/../../testprogs/blackbox
. $incdir/subunit.sh

#
# S-1-5-123456789 fails, but S-1-5-11 succeeds. Check that S-1-5-11 is
# mapped successfully with a GID in the 1000x range
#
wbinfo_some_mapped()
{
	output=`$VALGRIND $BINDIR/wbinfo --sids-to-unix-ids=S-1-5-123456789,S-1-5-11`
	test x"$?" = x"0" || {
		return 1
	}

	printf '%s' "$output" | grep -q 'S-1-5-123456789 -> unmapped' || {
		printf '%s' "$output"
		return 1
	}

	printf '%s' "$output" | grep -q 'S-1-5-11 -> gid 10000' || {
		printf '%s' "$output"
		return 1
	}

	return 0
}

testit "wbinfo some mapped" wbinfo_some_mapped || failed=`expr $failed + 1`

testok $0 $failed
