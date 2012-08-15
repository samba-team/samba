#!/bin/sh
if [ $# -lt 2 ]; then
cat <<EOF
Usage: run.sh VFSTEST PREFIX
EOF
exit 1;
fi

TESTBASE=`dirname $0`
VFSTEST=$1
PREFIX=$2
shift 2
ADDARGS="$*"

VFSTEST_PREFIX=vfstest
VFSTEST_TMPDIR=$(mktemp -d ${PREFIX}/${VFSTEST_PREFIX}_XXXXXX)

incdir=`dirname $0`/../../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

cd $VFSTEST_TMPDIR || exit 1

test_vfstest() 
{
    cmd='$VFSTEST -f $TESTBASE/vfstest.cmd $ADDARGS '
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "command failed"
	false
	return
    fi

    echo "$out" | grep "NT_STATUS_ACCESS_DENIED" >/dev/null 2>&1

    if [ $? = 0 ] ; then
	# got ACCESS_DENIED .. fail
	echo vfstest got NT_STATUS_ACCESS_DENIED
	false
    else
	true
    fi
}

testit "vfstest" test_vfstest || failed=`expr $failed + 1`

exit $failed
