#!/bin/sh

# Run some IP allocation unit tests.

cd $(dirname "$0")
export TESTS_SUBDIR=$(pwd)

test_dir=$(dirname "$TESTS_SUBDIR")

opts="-d"

for i ; do
    case "$i" in
	-v)
	    export TESTS_VERBOSE="yes"
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
    tests=$(ls testcases/*.[0-9][0-9][0-9].sh 2>/dev/null)
fi

"$test_dir/scripts/run_tests" $opts "$@" $tests || exit 1

echo "All OK"
exit 0
