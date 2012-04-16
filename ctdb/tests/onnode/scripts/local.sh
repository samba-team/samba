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

export ONNODE_TESTS_VAR_DIR="${TEST_SUBDIR}/var"
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

required_result ()
{
    required_rc="${1:-0}"
    required_output=$(cat)
}

simple_test ()
{
    _sort="cat"
    if [ "$1" = "-s" ] ; then
	shift
	_sort="sort"
    fi
    _out=$("$@" 2>&1)
    _rc=$?
    _out=$(echo "$_out" | $_sort )

    if [ "$_out" = "$required_output" -a $_rc = $required_rc ] ; then
	echo "PASSED"
    else
	cat <<EOF
CTDB_NODES_FILE="${CTDB_NODES_FILE}"
CTDB_BASE="$CTDB_BASE"
$(which ctdb)

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
