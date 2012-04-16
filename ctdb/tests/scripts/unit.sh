# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

. "${TEST_SCRIPTS_DIR}/common.sh"

# Common variables and functions for CTDB unit tests.

required_result ()
{
    required_rc="${1:-0}"
    required_output=$(cat)
}

local="${TEST_SUBDIR}/scripts/local.sh"
if [ -r "$local" ] ; then
    . "$local"
fi
