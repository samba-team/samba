# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Default to just "onnode".
: ${ONNODE:=onnode}

# Augment PATH with relevant stubs/ directory
stubs_dir="${TEST_SUBDIR}/stubs"
[ -d "${stubs_dir}" ] || die "Failed to locate stubs/ subdirectory"
PATH="${stubs_dir}:${PATH}"

[ -n "$TEST_VAR_DIR" ] || die "TEST_VAR_DIR unset"
export ONNODE_TESTS_VAR_DIR="${TEST_VAR_DIR}/unit_onnode"
if [ -d "$ONNODE_TESTS_VAR_DIR" ] ; then
	rm -r "$ONNODE_TESTS_VAR_DIR"
fi
mkdir -p "$ONNODE_TESTS_VAR_DIR"

setup_ctdb_base "$ONNODE_TESTS_VAR_DIR" "etc-ctdb" \
		functions

define_test ()
{
    _f=$(basename "$0")

    echo "$_f $1 - $2"
}

# Set output for ctdb command.  Option 1st argument is return code.
ctdb_set_output ()
{
    _out="$ONNODE_TESTS_VAR_DIR/ctdb.out"
    cat >"$_out"

    _rc="$ONNODE_TESTS_VAR_DIR/ctdb.rc"
    echo "${1:-0}" >"$_rc"

    test_cleanup "rm -f $_out $_rc"
}

extra_footer ()
{
    cat <<EOF
--------------------------------------------------
CTDB_NODES_FILE="${CTDB_NODES_FILE}"
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

    if $TEST_COMMAND_TRACE ; then
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
