# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Set indirectly by run_tests at top level.
unset CTDB_NODES_SOCKETS

# Default to just "onnode".
: ${ONNODE:=onnode}

# Augment PATH with relevant stubs/ directories.

if [ -d "${TEST_SUBDIR}/stubs" ] ; then
    PATH="${TEST_SUBDIR}/stubs:$PATH"
fi

# Find CTDB nodes file.
if [ -z "$CTDB_NODES_FILE" ] ; then
    if [ -r "${TEST_SUBDIR}/nodes" ] ; then
	CTDB_NODES_FILE="${TEST_SUBDIR}/nodes"
    else
	CTDB_NODES_FILE="${CTDB_BASE:-/etc/ctdb}/nodes"
    fi
fi

export CTDB_NODES_FILE

export ONNODE_TESTS_VAR_DIR="${TEST_VAR_DIR}/unit_onnode"
mkdir -p "$ONNODE_TESTS_VAR_DIR"

if [ -z "$CTDB_BASE" ] ; then
    export CTDB_BASE=$(dirname "$CTDB_NODES_FILE")
fi

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

    trap "rm -f $_out $_rc" 0
}

_extra_header ()
{
    cat <<EOF
CTDB_NODES_FILE="${CTDB_NODES_FILE}"
CTDB_BASE="$CTDB_BASE"
$(which ctdb)

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

    # Can't do this inline or it affects return code
    _extra_header="$(_extra_header)"

    # Get the return code back into $?
    (exit $_rc)

    result_check "$_extra_header"
}
