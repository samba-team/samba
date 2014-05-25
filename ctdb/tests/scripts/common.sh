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
if [ -d "$_test_bin_dir" ] ; then
    PATH="${_test_bin_dir}:$PATH"
fi

# Print a message and exit.
die ()
{
    echo "$1" >&2 ; exit ${2:-1}
}
