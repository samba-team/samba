#!/bin/sh

test_dir=$(dirname "$0")

# Allow options to be passed to this script.  However, if any options
# are passed there must be a "--" between the options and the tests.
# This makes it easy to handle options that take arguments.
opts=""
case "$1" in
    -*)
	while [ -n "$1" ] ; do
	    case "$1" in
		--) shift ; break ;;
		*) opts="$opts $1" ; shift ;;
	    esac
	done
esac

if [ -n "$1" ] ; then
    "${test_dir}/scripts/run_tests" -s $opts "$@" || exit 1
else
    cd "$test_dir"

    # By default, don't bother with unit tests
    dirs="simple complex"

    ./scripts/run_tests -s $opts $dirs || exit 1
fi

echo "All OK"
exit 0
