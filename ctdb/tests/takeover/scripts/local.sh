# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

test_prog="ctdb_takeover_tests ipalloc"

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

extra_footer ()
{
    cat <<EOF
--------------------------------------------------
Algorithm: $CTDB_IP_ALGORITHM
--------------------------------------------------
EOF
}

simple_test ()
{
    unit_test $VALGRIND $test_prog "$@"
}
