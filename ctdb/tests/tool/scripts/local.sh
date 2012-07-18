# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

if "$TEST_VERBOSE" ; then
    debug () { echo "$@" ; }
else
    debug () { : ; }
fi

define_test ()
{
    _f=$(basename "$0" ".sh")

    case "$_f" in
	func.*)
	    _func="${_f#func.}"
	    _func="${_func%.*}" # Strip test number
	    test_prog="ctdb_tool_libctdb ${_func}"
	    ;;
	stubby.*)
	    _cmd="${_f#stubby.}"
	    _cmd="${_cmd%.*}" # Strip test number
	    test_prog="ctdb_tool_stubby ${_cmd}"
	    ;;
	*)
	    die "Unknown pattern for testcase \"$_f\""
    esac

    printf "%-28s - %s\n" "$_f" "$1"
}

setup_natgw ()
{
    debug "Setting up NAT gateway"

    natgw_config_dir="${TEST_VAR_DIR}/natgw_config"
    mkdir -p "$natgw_config_dir"

    # These will accumulate, 1 per test... but will be cleaned up at
    # the end.
    export CTDB_NATGW_NODES=$(mktemp --tmpdir="$natgw_config_dir")

    cat >"$CTDB_NATGW_NODES"
}

simple_test ()
{
    # Most of the tests when the tool fails will have a date/time/pid
    # prefix.  Strip that because it isn't possible to match it.
    if [ $required_rc -ne 0 ]  ; then
	OUT_FILTER='s@^[0-9/]+\ [0-9:\.]+\ \[[\ 0-9]+\]:@DATE\ TIME\ \[PID\]:@'
    fi

    _out=$($VALGRIND $test_prog "$@" 2>&1)

    result_check
}
