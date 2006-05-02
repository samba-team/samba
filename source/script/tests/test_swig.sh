#!/bin/sh

if [ $# -ne 0 ]; then
    cat <<EOF
Usage: test_swig.sh
EOF
    exit 1;
fi

incdir=`dirname $0`
. $incdir/test_functions.sh

failed=0

export PYTHONPATH=lib/tdb/swig:lib/ldb/swig:scripting/swig:$PYTHONPATH
export LD_LIBRARY_PATH=bin:$LD_LIBRARY_PATH

echo Testing tdb wrappers
scripting/swig/torture/torture_tdb.py || failed=`expr $failed + 1`

echo Testing ldb wrappers
scripting/swig/torture/torture_ldb.py || failed=`expr $failed + 1`

testok $0 $failed
