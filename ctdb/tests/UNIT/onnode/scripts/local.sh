# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Default to just "onnode".
: ${ONNODE:=onnode}

# Augment PATH with relevant stubs/ directory
stubs_dir="${CTDB_TEST_SUITE_DIR}/stubs"
[ -d "${stubs_dir}" ] || die "Failed to locate stubs/ subdirectory"
PATH="${stubs_dir}:${PATH}"

setup_ctdb_base "$CTDB_TEST_TMP_DIR" "etc-ctdb" \
		functions

define_test ()
{
    _f=$(basename "$0")

    echo "$_f $1 - $2"
}

# Set output for ctdb command.  Option 1st argument is return code.
ctdb_set_output ()
{
    _out="${CTDB_TEST_TMP_DIR}/ctdb.out"
    cat >"$_out"

    _rc="${CTDB_TEST_TMP_DIR}/ctdb.rc"
    echo "${1:-0}" >"$_rc"

    test_cleanup "rm -f $_out $_rc"
}

extra_footer ()
{
    cat <<EOF
--------------------------------------------------
CTDB_BASE="$CTDB_BASE"
ctdb client is $(which ctdb)
--------------------------------------------------
EOF
}

simple_test ()
{
    _sort="cat"
    if [ "$1" = "-s" ] ; then
	shift
	_sort="sort"
    fi

    if $CTDB_TEST_COMMAND_TRACE ; then
	_onnode=$(which "$1") ; shift
	_out=$(bash -x "$_onnode" "$@" 2>&1)
    else
	_out=$("$@" 2>&1)
    fi
    _rc=$?
    _out=$(echo "$_out" | $_sort )

    # Get the return code back into $?
    (exit $_rc)

    result_check
}
