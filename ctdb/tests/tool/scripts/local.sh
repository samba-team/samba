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
	    test_prog="ctdb_functest ${_func}"
	    ;;
	stubby.*)
	    _cmd="${_f#stubby.}"
	    _cmd="${_cmd%.*}" # Strip test number
	    test_prog="ctdb_stubtest ${_cmd}"
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

setup_nodes ()
{
    debug "Setting up CTDB_NODES"

    # These will accumulate, 1 per test... but will be cleaned up at
    # the end.
    export CTDB_NODES=$(mktemp --tmpdir="$TEST_VAR_DIR")

    cat >"$CTDB_NODES"
}

simple_test ()
{
    _out=$($VALGRIND $test_prog "$@" 2>&1)

    result_check
}
