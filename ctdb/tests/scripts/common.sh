# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Common variables and functions for all CTDB tests.

# This expands the most probable problem cases like "." and "..".
TEST_SUBDIR=$(dirname "$0")
if [ $(dirname "$TEST_SUBDIR") = "." ] ; then
    TEST_SUBDIR=$(cd "$TEST_SUBDIR" ; pwd)
fi

CTDB_DIR=$(dirname $(dirname "$TEST_SUBDIR"))

_tests_dir=$(dirname "$TEST_SUBDIR")
[ -n "$TEST_BIN_DIR" ] || TEST_BIN_DIR="${_tests_dir}/bin"
[ -n "$CTDB_TOOLS_DIR" ] || CTDB_TOOLS_DIR="${CTDB_DIR}/tools"
PATH="${TEST_BIN_DIR}:${CTDB_TOOLS_DIR}:${PATH}"

# Print a message and exit.
die ()
{
    echo "$1" >&2 ; exit ${2:-1}
}
