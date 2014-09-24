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

ok ()
{
    required_result 0 "$@"
}

ok_null ()
{
    ok --
}

result_print ()
{
    _passed="$1"
    _out="$2"
    _rc="$3"
    _extra_header="$4"

    if "$TEST_VERBOSE" || ! $_passed ; then
	if [ -n "$_extra_header" ] ; then
	    cat <<EOF

##################################################
$_extra_header
EOF
	fi

cat <<EOF
--------------------------------------------------
Output (Exit status: ${_rc}):
--------------------------------------------------
EOF
	echo "$_out" | cat $TEST_CAT_RESULTS_OPTS
    fi

    if ! $_passed ; then
	cat <<EOF
--------------------------------------------------
Required output (Exit status: ${required_rc}):
--------------------------------------------------
EOF
	echo "$required_output" | cat $TEST_CAT_RESULTS_OPTS

	if $TEST_DIFF_RESULTS ; then
	    _outr=$(mktemp)
	    echo "$required_output" >"$_outr"

	    _outf=$(mktemp)
	    echo "$_fout" >"$_outf"

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
    _extra_footer="$2"

    if "$TEST_VERBOSE" || ! $_passed ; then
	if [ -n "$_extra_footer" ] ; then
	    cat <<EOF
--------------------------------------------------
$_extra_footer
--------------------------------------------------
EOF
	fi
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

    _extra_header="$1"

    _fout=$(echo "$_out" | result_filter)

    if [ "$_fout" = "$required_output" -a $_rc = $required_rc ] ; then
	_passed=true
    else
	_passed=false
    fi

    result_print "$_passed" "$_out" "$_rc" "$_extra_header"
    result_footer "$_passed"
}

local="${TEST_SUBDIR}/scripts/local.sh"
if [ -r "$local" ] ; then
    . "$local"
fi
