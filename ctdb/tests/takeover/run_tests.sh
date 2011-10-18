#!/bin/sh

# Run some IP allocation unit tests.

cd $(dirname "$0")
export TAKEOVER_TESTS_DIR=$(pwd)

test_dir=$(dirname "$TAKEOVER_TESTS_DIR")

opts="-d"

for i ; do
    case "$i" in
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
