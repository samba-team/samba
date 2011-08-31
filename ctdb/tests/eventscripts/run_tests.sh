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
	-T)
	    # This will cause tests to fail but is good for debugging
	    # individual tests when they fail.
	    export EVENTSCRIPTS_TESTS_TRACE="sh -x"
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
