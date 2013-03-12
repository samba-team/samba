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

# We could pass in the --option=... via tests.py as ADDARGS
# Atm i've choosen to specify them here:

MYARGS1="--option=vfsobjects=catia"
MYARGS2="--option=catia:mappings=0x22:0xa8,0x2a:0xa4,0x2f:0xf8,0x3a:0xf7,0x3c:0xab,0x3e:0xbb,0x3f:0xbf,0x5c:0xff,0x7c:0xa6,0x20:0xb1"

# vars for the translation test:
# a) here for unix-to-windows test
UNIX_FILE="a\\a:a*a?a<a>a|a"
# translated window file name
WIN_FILE="aÿa÷a¤a¿a«a»a¦a"

# b) here for windows-to-unix test
WIN_DIR="dir_aÿa÷a¤a¿a«a»a¦a"
# translated unix directory name
UNIX_DIR="dir_a\a:a*a?a<a>a|a"

incdir=`dirname $0`/../../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

cd $VFSTEST_TMPDIR || exit 1

# create unix file in tmpdir
touch $UNIX_FILE || exit 1

# test "translate" unix-to-windows
test_vfstest() 
{
    cmd='$VFSTEST -f $TESTBASE/vfstest.cmd $MYARGS1 $MYARGS2 $ADDARGS '
    out=`eval $cmd`
    ret=$?

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "command failed"
	false
	return
    fi

    echo "$out" | grep $WIN_FILE >/dev/null 2>&1

    if [ $? = 0 ] ; then
	echo "ALL IS WORKING"
	true
    else
	false
    fi
}

# test the mkdir call with special windows chars
# and then check the created unix directory name
test_vfstest_dir() 
{
    cmd='$VFSTEST -f $TESTBASE/vfstest1.cmd $MYARGS1 $MYARGS2 $ADDARGS '
    out=`eval $cmd`
    ret=$?

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "command failed"
	false
	return
    fi

    NUM=`find $UNIX_DIR | wc -l`
    if [ $NUM -ne 1 ] ; then
	echo "Cannot find $UNIX_DIR"
	false
    else
	true
    fi
}

testit "vfstest_catia" test_vfstest || failed=`expr $failed + 1`

if [ $failed = 0 ] ; then
    testit "vfstest1_catia" test_vfstest_dir || failed=`expr $failed + 1`
fi

# Cleanup: remove tempdir
rm -R $VFSTEST_TMPDIR

exit $failed
