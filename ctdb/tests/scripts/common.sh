# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Common variables and functions for all CTDB tests.

# This expands the most probable problem cases like "." and "..".
TEST_SUBDIR=$(dirname "$0")
if [ $(dirname "$TEST_SUBDIR") = "." ] ; then
    TEST_SUBDIR=$(cd "$TEST_SUBDIR" ; pwd)
fi

CTDB_DIR=$(dirname $(dirname "$TEST_SUBDIR"))

# Print a message and exit.
die ()
{
    echo "$1" >&2 ; exit ${2:-1}
}
