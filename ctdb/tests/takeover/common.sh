# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Print a message and exit.
die () { echo "$@" >&2 ; exit 1 ; }

test_prog="$(dirname ${TAKEOVER_TESTS_DIR})/bin/ctdb_takeover_tests ctdb_takeover_run_core"

define_test ()
{
    _f="$0"
    _f="${_f#./}"  # strip leading ./
    _f="${_f#testcases/}"  # strip leading testcases/
    _f="${_f%.sh}" # strip off .sh suffix if any

    case "$_f" in
	nondet.*)
	    algorithm="nondet"
	    CTDB_LCP2="no"
	    ;;
	lcp2.*)
	    algorithm="lcp2"
	    export CTDB_LCP2="yes"
	    ;;
	*)
	    die "Unknown algorithm for testcase \"$_f\""
    esac

    printf "%-12s - %s\n" "$_f" "$1"
}

required_result ()
{
    required_rc="${1:-0}"
    required_output=$(cat)
}

simple_test ()
{
    _states="$1"
    _out=$($test_prog $_states 2>&1)
    _rc=$?

    if [ "$algorithm" = "lcp2" -a -n "$CTDB_TEST_LOGLEVEL" ] ; then
	OUT_FILTER='s@^.*:@DATE TIME \[PID\]:@'
    fi

    if [ -n "$OUT_FILTER" ] ; then
	_fout=$(echo "$_out" | sed -r "$OUT_FILTER")
    else
	_fout="$_out"
    fi

    if [ "$_fout" = "$required_output" -a $_rc = $required_rc ] ; then
	echo "PASSED"
    else
	cat <<EOF
Algorithm: $algorithm

##################################################
Required output (Exit status: ${required_rc}):
##################################################
$required_output
##################################################
Actual output (Exit status: ${_rc}):
##################################################
$_out
EOF
	return 1
    fi
}
