#!/bin/sh

# Eventscript unit test harness.

cd $(dirname "$0")
export EVENTSCRIPTS_TESTS_DIR=$(pwd)

test_dir=$(dirname "$EVENTSCRIPTS_TESTS_DIR")

opts="-d"

for i ; do
    case "$i" in
	-v)
	    export EVENTSCRIPT_TESTS_VERBOSE="yes"
	    shift
	    ;;
	-*)
	    opts="$opts $i"
	    shift
	    ;;
	*)
	    break
    esac
done

tests=""
if [ -z "$*" ] ; then
    tests=$(ls simple/[0-9][0-9].*.*.[0-9][0-9][0-9].sh simple/[0-9][0-9].*.*.[0-9][0-9][0-9]/run_test.sh 2>/dev/null)
fi

"$test_dir/scripts/run_tests" $opts "$@" $tests || exit 1

exit 0
