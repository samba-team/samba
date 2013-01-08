#!/bin/sh

BINDIR=$1

if [ -n "$TEST_DATA_PREFIX" ]; then
	LDB_URL="$TEST_DATA_PREFIX/tdbtest.ldb"
	PYDESTDIR="$TEST_DATA_PREFIX"
else
	LDB_URL="tdbtest.ldb"
	PYDESTDIR="/tmp"
fi
mkdir $PYDESTDIR/tmp
export LDB_URL

PATH=$BINDIR:$PATH
export PATH

if [ -z "$LDBDIR" ]; then
    LDBDIR=`dirname $0`/..
    export LDBDIR
fi

cd $LDBDIR

rm -f $LDB_URL*

cat <<EOF | $VALGRIND ldbadd || exit 1
dn: @MODULES
@LIST: rdn_name
EOF

$VALGRIND ldbadd $LDBDIR/tests/init.ldif || exit 1

. $LDBDIR/tests/test-generic.sh

. $LDBDIR/tests/test-extended.sh

. $LDBDIR/tests/test-tdb-features.sh

. $LDBDIR/tests/test-controls.sh

which python >/dev/null 2>&1
if [ $? -eq 0 ]; then
	SELFTEST_PREFIX=$PYDESTDIR PYTHONPATH=$BINDIR/python python $LDBDIR/tests/python/api.py
fi
