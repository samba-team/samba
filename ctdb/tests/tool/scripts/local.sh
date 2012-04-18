# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

test_bin="$(dirname ${TEST_SUBDIR})/bin"

define_test ()
{
    _f=$(basename "$0" ".sh")

    case "$_f" in
	func.*)
	    _func="${_f#func.}"
	    _func="${_func%.*}" # Strip test number
	    test_prog="${test_bin}/ctdb_tool_libctdb ${_func}"
	    ;;
	stubby.*)
	    _cmd="${_f#stubby.}"
	    _cmd="${_cmd%.*}" # Strip test number
	    test_prog="${test_bin}/ctdb_tool_stubby ${_cmd}"
	    ;;
	*)
	    die "Unknown pattern for testcase \"$_f\""
    esac

    printf "%-28s - %s\n" "$_f" "$1"
}

simple_test ()
{
    # Most of the tests when the tool fails will have a date/time/pid
    # prefix.  Strip that because it isn't possible to match it.
    if [ $required_rc -ne 0 ]  ; then
	OUT_FILTER='s@^[0-9/]+\ [0-9:\.]+\ \[[\ 0-9]+\]:@DATE\ TIME\ \[PID\]:@'
    fi

    _out=$($test_prog "$@" 2>&1)

    result_check
}
