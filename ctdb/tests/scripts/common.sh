# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Common variables and functions for all CTDB tests.

# This expands the most probable problem cases like "." and "..".
TEST_SUBDIR=$(dirname "$0")
if [ $(dirname "$TEST_SUBDIR") = "." ] ; then
    TEST_SUBDIR=$(cd "$TEST_SUBDIR" ; pwd)
fi

_test_dir=$(dirname "$TEST_SUBDIR")

# If we are running from within the source tree then, depending on the
# tests that we're running, we may need to add the top level bin/ and
# tools/ subdirectories to $PATH.  This means we need a way of
# determining if we're running from within the source tree.  There is
# no use looking outside the tests/ subdirectory because anything
# above that level may be meaningless and outside our control.
# Therefore, we'll use existence of $_test_dir/run_tests.sh to
# indicate that we're running in-tree - on a system where the tests
# have been installed, this file will be absent (renamed and placed in
# some bin/ directory).
if [ -f "${_test_dir}/run_tests.sh" ] ; then
    ctdb_dir=$(dirname "$_test_dir")

    _tools_dir="${ctdb_dir}/tools"
    if [ -d "$_tools_dir" ] ; then
	PATH="${_tools_dir}:$PATH"
    fi
fi

_test_bin_dir="${TEST_BIN_DIR:-${ctdb_dir}/bin}"
case "$_test_bin_dir" in
    /*) : ;;
    *) _test_bin_dir="${PWD}/${_test_bin_dir}" ;;
esac
if [ -d "$_test_bin_dir" ] ; then
    PATH="${_test_bin_dir}:$PATH"
fi

# Print a message and exit.
die ()
{
    echo "$1" >&2 ; exit ${2:-1}
}

# Wait until either timeout expires or command succeeds.  The command
# will be tried once per second, unless timeout has format T/I, where
# I is the recheck interval.
wait_until ()
{
    local timeout="$1" ; shift # "$@" is the command...

    local interval=1
    case "$timeout" in
	*/*)
	    interval="${timeout#*/}"
	    timeout="${timeout%/*}"
    esac

    local negate=false
    if [ "$1" = "!" ] ; then
	negate=true
	shift
    fi

    echo -n "<${timeout}|"
    local t=$timeout
    while [ $t -gt 0 ] ; do
	local rc=0
	"$@" || rc=$?
	if { ! $negate && [ $rc -eq 0 ] ; } || \
	    { $negate && [ $rc -ne 0 ] ; } ; then
	    echo "|$(($timeout - $t))|"
	    echo "OK"
	    return 0
	fi
	local i
	for i in $(seq 1 $interval) ; do
	    echo -n .
	done
	t=$(($t - $interval))
	sleep $interval
    done

    echo "*TIMEOUT*"

    return 1
}
