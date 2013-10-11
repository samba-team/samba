#!/bin/sh

test_dir=$(dirname "$0")

case $(basename "$0") in
    *run_cluster_tests*)
	# Running on a cluster:
	# * print summary, run any integration tests against cluster
	# * default to running: all integration tests, no unit tests
	opts="-s"
	tests="simple complex"
	;;
    *)
	# Running on local machine:
	# * print summary, run any integration tests against local daemons
	# * default to running: all unit tests, simple integration tests
	opts="-s -l"
	tests="onnode takeover tool eventscripts simple"
	# If running in the source tree then use a fixed TEST_VAR_DIR.
	# If this script is installed using the INSTALL script then
	# TEST_BIN_DIR will be set, so use this as the test.
	if [ -z "$TEST_BIN_DIR" ] ; then
	    opts="${opts} -V ${test_dir}/var"
	fi
esac

# Allow options to be passed to this script.  However, if any options
# are passed there must be a "--" between the options and the tests.
# This makes it easy to handle options that take arguments.
case "$1" in
    -*)
	while [ -n "$1" ] ; do
	    case "$1" in
		--) shift ; break ;;
		*) opts="$opts $1" ; shift ;;
	    esac
	done
esac

# If no tests are specified, then run the defaults.
[ -n "$1" ] || set -- $tests

"${test_dir}/scripts/run_tests" $opts "$@" || exit 1

echo "All OK"
exit 0
