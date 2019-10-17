# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

. "${TEST_SCRIPTS_DIR}/common.sh"

# Common variables and functions for CTDB unit tests.

trap -- '' PIPE

# Set the required result for a test.
# - Argument 1 is exit code.
# - Argument 2, if present is the required test output but "--"
#   indicates empty output.
# If argument 2 is not present or null then read required test output
# from stdin.
required_result ()
{
    required_rc="${1:-0}"
    if [ -n "$2" ] ; then
	if [ "$2" = "--" ] ; then
	    required_output=""
	else
	    required_output="$2"
	fi
    else
	if ! tty -s ; then
	    required_output=$(cat)
	else
	    required_output=""
	fi
    fi
}

required_error ()
{
	rc=$(errcode $1)
	shift
	required_result $rc "$@"
}

ok ()
{
    required_result 0 "$@"
}

ok_null ()
{
    ok --
}

reset_extra_header ()
{
    # Re-define this function to output extra header information
    extra_header ()
    {
	:
    }
}

reset_extra_footer ()
{
    # Re-define this function to output extra footer information
    extra_footer ()
    {
	:
    }
}

reset_extra_header
reset_extra_footer

result_print ()
{
    _passed="$1"
    _out="$2"
    _rc="$3"

    if "$CTDB_TEST_VERBOSE" || ! $_passed ; then
	extra_header

cat <<EOF
--------------------------------------------------
Output (Exit status: ${_rc}):
--------------------------------------------------
EOF
	# Avoid echo, which might expand unintentional escapes
	printf '%s\n' "$_out" | result_filter | cat $CTDB_TEST_CAT_RESULTS_OPTS
    fi

    if ! $_passed ; then
	cat <<EOF
--------------------------------------------------
Required output (Exit status: ${required_rc}):
--------------------------------------------------
EOF
	# Avoid echo, which might expand unintentional escapes
	printf '%s\n' "$required_output" | cat $CTDB_TEST_CAT_RESULTS_OPTS

	if $CTDB_TEST_DIFF_RESULTS ; then
	    _outr=$(mktemp)
	    # Avoid echo, which might expand unintentional escapes
	    printf '%s\n' "$required_output" >"$_outr"

	    _outf=$(mktemp)
	    # Avoid echo, which might expand unintentional escapes
	    printf '%s\n' "$_fout" >"$_outf"

	    cat <<EOF
--------------------------------------------------
Diff:
--------------------------------------------------
EOF
	    diff -u "$_outr" "$_outf" | cat -A
	    rm "$_outr" "$_outf"
	fi
    fi
}

result_footer ()
{
    _passed="$1"

    if "$CTDB_TEST_VERBOSE" || ! $_passed ; then
	extra_footer
    fi

    if $_passed ; then
	echo "PASSED"
	return 0
    else
	echo
	echo "FAILED"
	return 1
    fi
}

# Result filtering is (usually) used to replace the date/time/PID
# prefix on some CTDB tool/client log messages with the literal string
# "DATE TIME [PID]".  This allows tests to loosely match this output,
# since it can't otherwise be matched.
result_filter_default ()
{
    _date_time_pid='[0-9/][0-9/]*\ [0-9:\.][0-9:\.]*\ \[[\ 0-9][\ 0-9]*\]'
    sed -e "s@^${_date_time_pid}:@DATE\ TIME\ \[PID\]:@"
}
TEST_DATE_STAMP=""

# Override this function to customise output filtering.
result_filter ()
{
    result_filter_default
}

result_check ()
{
    _rc=$?

    # Avoid echo, which might expand unintentional escapes
    _fout=$(printf '%s\n' "$_out" | result_filter)

    if [ "$_fout" = "$required_output" -a $_rc = $required_rc ] ; then
	_passed=true
    else
	_passed=false
    fi

    result_print "$_passed" "$_out" "$_rc"
    result_footer "$_passed"
}

test_fail ()
{
    _passed=false
    return 1
}

test_header_default ()
{
    echo "=================================================="
    echo "Running \"$*\""
}

reset_test_header ()
{
    # Re-define this function to get different header
    test_header ()
    {
        test_header_default "$@"
    }
}

reset_test_header

# Simple test harness for running binary unit tests
unit_test ()
{
    test_header "$@"

    _wrapper="$VALGRIND"
    if $CTDB_TEST_COMMAND_TRACE ; then
	_wrapper="strace"
    fi
    _out=$($_wrapper "$@" 2>&1)

    result_check || exit $?
}

# Simple test harness for running shell script unit tests
script_test ()
{
    test_header "$@"

    _shell=""
    if ${CTDB_TEST_COMMAND_TRACE} ; then
	_shell="sh -x"
    else
	_shell="sh"
    fi

    _out=$($_shell "$@" 2>&1)

    result_check || exit $?
}

# Simple test harness for running tests without tracing
unit_test_notrace ()
{
    test_header "$@"

    _out=$("$@" 2>&1)

    result_check || exit $?
}

test_cleanup_hooks=""

test_cleanup ()
{
    test_cleanup_hooks="${test_cleanup_hooks}${test_cleanup_hooks:+ ; }$*"
}

trap 'eval $test_cleanup_hooks' 0

local="${CTDB_TEST_SUITE_DIR}/scripts/local.sh"
if [ -r "$local" ] ; then
    . "$local"
fi
