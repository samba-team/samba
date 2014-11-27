#!/bin/sh
#
# Blackbox tests for the "net registry check" command.
#
# Copyright (C) 2011 Björn Baumbach <bb@sernet.de>

if [ $# -lt 5 ]; then
	echo "Usage: test_net_registry.sh SCRIPTDIR SERVERCONFFILE NET CONFIGURATION DBWRAP_TOOL"
	exit 1
fi

SCRIPTDIR="$1"
SERVERCONFFILE="$2"
NET="$3"
CONFIGURATION="$4"
DBWRAP_TOOL="$5 --persistent"

NET="$VALGRIND ${NET:-$BINDIR/net} $CONFIGURATION"

NETREG="${NET} registry"
REGORIG="$(grep 'state directory = ' $SERVERCONFFILE | sed 's/[^=]*=//')/registry.tdb"
REG=$REGORIG.wip

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

# run registry check and filter allowed errors
regcheck()
{
	ALLOWEDERR="Check database:|INFO: version ="
	ERRSTR=$(${NETREG} check $REG $@ 2>&1 | egrep -v "$ALLOWEDERR")
}

# try to repair registry
regrepair()
{
	regcheck -a
}

# check if $ERRSTR contains expected error
checkerr()
{
	EXPERR=$1

	ERRCNT=$(echo "$ERRSTR" | grep "$EXPERR" | wc -l)
	return $ERRCNT
}

regchecknrepair()
{
	EXPERR="$1"
	EXPERRCNT="$2"

	regcheck
	checkerr "$EXPERR"
	test "$?" -eq "$ERRCNT" || {
		echo "Expected $EXPERRCNT of error $EXPERR. Received $ERRCNT"
		return 1
	}

	regrepair
	regcheck
	test "x$ERRSTR" = "x" || {
		echo "Error: Can't repair database"
		return 1
	}
}

test_simple()
(
	ERRSTR=""
	cp $REGORIG $REG

	regcheck
	test "x$ERRSTR" = "x" || {
		echo $ERRSTR
		return 1
	}
)

test_damage()
{
	diff $REGORIG $REG
}

test_duplicate()
(
	ERRSTR=""
	$DBWRAP_TOOL $REG store 'HKLM/SOFTWARE' hex '02000000534F4654574152450053595354454D00'

	regchecknrepair "Duplicate subkeylist" 1
)

test_slashes()
(
	ERRSTR=""
	$DBWRAP_TOOL $REG store 'HKLM/SOFTWARE' hex '02000000534F4654574152450053595354454D00'

	regchecknrepair "Unnormal key:" 1
)

test_uppercase()
(
	ERRSTR=""
	$DBWRAP_TOOL $REG store 'HKLM\Software' hex '02000000534F4654574152450053595354454D00'

	regchecknrepair "Unnormal key:" 1
)

test_strangeletters()
(
	ERRSTR=""
	$DBWRAP_TOOL $REG store 'HKLM\SOFTWARE' hex '02000000534F4654574FABFABFABFAB354454D00'

	regchecknrepair "Conversion error: Incomplete multibyte sequence" 1
)

testit "simple" \
	test_simple || \
	failed=`expr $failed + 1`

testit "damages_registry" \
	test_damage || \
	failed=`expr $failed + 1`

testit "duplicate" \
	test_duplicate || \
	failed=`expr $failed + 1`

testit "slashes" \
	test_slashes || \
	failed=`expr $failed + 1`

testit "uppercase" \
	test_uppercase || \
	failed=`expr $failed + 1`

#Can't repair this atm
#testit "strangeletters" \
#	test_strangeletters || \
#	failed=`expr $failed + 1`

testok $0 $failed

