# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

test_prog="ctdb_takeover_tests ctdb_takeover_run_core"

define_test ()
{
    _f=$(basename "$0" ".sh")

    export CTDB_IP_ALGORITHM="${_f%%.*}"
    case "$CTDB_IP_ALGORITHM" in
	lcp2|nondet|det) : ;;
	*) die "Unknown algorithm for testcase \"$_f\"" ;;
    esac

    printf "%-12s - %s\n" "$_f" "$1"
}

simple_test ()
{
    _out=$($VALGRIND $test_prog "$@" 2>&1)

    result_check "Algorithm: $CTDB_IP_ALGORITHM"
}
