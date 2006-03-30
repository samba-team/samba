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

export PYTHONPATH=scripting/swig:$PYTHONPATh

scripting/swig/torture/torture_tdb.py || failed=`expr $failed + 1`

testok $0 $failed
