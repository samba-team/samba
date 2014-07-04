#!/bin/bash

usage() {
    cat <<EOF
Usage: $0 [OPTIONS] [TESTS]

Options:
  -A		Use "cat -A" to print test output (only some tests)
  -c		Run integration tests on a cluster
  -C		Clean up - kill daemons and remove TEST_VAR_DIR when done
  -d		Print descriptions of tests instead of filenames (dodgy!)
  -D		Show diff between failed/expected test output (some tests only)
  -e		Exit on the first test failure
  -H		No headers - for running single test with other wrapper
  -N		Don't print summary of tests results after running all tests
  -q		Quiet - don't show tests being run (hint: use with -s)
  -S            Enable socket wrapper
  -v		Verbose - print test output for non-failures (only some tests)
  -V <dir>	Use <dir> as TEST_VAR_DIR
  -x		Trace this script with the -x option
  -X		Trace certain scripts run by tests using -x (only some tests)
EOF
    exit 1
}

# Print a message and exit.
die ()
{
    echo "$1" >&2 ; exit ${2:-1}
}

######################################################################

with_summary=true
with_desc=false
quiet=false
exit_on_fail=false
no_header=false
socket_wrapper=false

export TEST_VERBOSE=false
export TEST_COMMAND_TRACE=false
export TEST_CAT_RESULTS_OPTS=""
export TEST_DIFF_RESULTS=false
export TEST_LOCAL_DAEMONS
[ -n "$TEST_LOCAL_DAEMONS" ] || TEST_LOCAL_DAEMONS=3
export TEST_VAR_DIR=""
export TEST_CLEANUP=false

temp=$(getopt -n "$prog" -o "AcCdDehHNqSvV:xX" -l help -- "$@")

[ $? != 0 ] && usage

eval set -- "$temp"

while true ; do
    case "$1" in
	-A) TEST_CAT_RESULTS_OPTS="-A" ; shift ;;
	-c) TEST_LOCAL_DAEMONS="" ; shift ;;
	-C) TEST_CLEANUP=true ; shift ;;
	-d) with_desc=true ; shift ;;  # 4th line of output is description
	-D) TEST_DIFF_RESULTS=true ; shift ;;
	-e) exit_on_fail=true ; shift ;;
	-H) no_header=true ; shift ;;
	-N) with_summary=false ; shift ;;
	-q) quiet=true ; shift ;;
	-S) socket_wrapper=true ; shift ;;
	-v) TEST_VERBOSE=true ; shift ;;
	-V) TEST_VAR_DIR="$2" ; shift 2 ;;
	-x) set -x; shift ;;
	-X) TEST_COMMAND_TRACE=true ; shift ;;
	--) shift ; break ;;
	*) usage ;;
    esac
done

case $(basename "$0") in
    *run_cluster_tests*)
	# Running on a cluster...  same as -c
	TEST_LOCAL_DAEMONS=""
	;;
esac

if $quiet ; then
    show_progress() { cat >/dev/null ; }
else
    show_progress() { cat ; }
fi

######################################################################

ctdb_test_begin ()
{
    local name="$1"

    teststarttime=$(date '+%s')
    testduration=0

    echo "--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--"
    echo "Running test $name ($(date '+%T'))"
    echo "--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--"
}

ctdb_test_end ()
{
    local name="$1" ; shift
    local status="$1" ; shift
    # "$@" is command-line

    local interp="SKIPPED"
    local statstr=" (reason $*)"
    if [ -n "$status" ] ; then
	if [ $status -eq 0 ] ; then
	    interp="PASSED"
	    statstr=""
	    echo "ALL OK: $*"
	else
	    interp="FAILED"
	    statstr=" (status $status)"
	fi
    fi

    testduration=$(($(date +%s)-$teststarttime))

    echo "=========================================================================="
    echo "TEST ${interp}: ${name}${statstr} (duration: ${testduration}s)"
    echo "=========================================================================="

}

ctdb_test_run ()
{
    local name="$1" ; shift

    [ -n "$1" ] || set -- "$name"

    $no_header || ctdb_test_begin "$name"

    local status=0
    "$@" || status=$?

    $no_header || ctdb_test_end "$name" "$status" "$*"

    return $status
}

######################################################################

tests_total=0
tests_passed=0
tests_failed=0
summary=""

if ! which mktemp >/dev/null 2>&1 ; then
    # Not perfect, but it will do...
    mktemp ()
    {
	_dir=false
	if [ "$1" = "-d" ] ; then
	    _dir=true
	fi
	_t="${TMPDIR:-/tmp}/tmp.$$.$RANDOM"
	(
	    umask 077
	    if $_dir ; then
		mkdir "$_t"
	    else
		>"$_t"
	    fi
	)
	echo "$_t"
    }
fi

tf=$(mktemp)
sf=$(mktemp)

set -o pipefail

run_one_test ()
{
    _f="$1"

    [ -x "$_f" ] || die "test \"$_f\" is not executable"
    tests_total=$(($tests_total + 1))

    ctdb_test_run "$_f" | tee "$tf" | show_progress
    status=$?
    if [ $status -eq 0 ] ; then
	tests_passed=$(($tests_passed + 1))
    else
	tests_failed=$(($tests_failed + 1))
    fi
    if $with_summary ; then
	if [ $status -eq 0 ] ; then
	    _t=" PASSED "
	else
	    _t="*FAILED*"
	fi
	if $with_desc ; then
	    desc=$(tail -n +4 $tf | head -n 1)
	    _f="$desc"
	fi
	echo "$_t $_f" >>"$sf"
    fi
}

find_and_run_one_test ()
{
    _t="$1"
    _dir="$2"

    _f="${_dir}${_dir:+/}${_t}"

    if [ -d "$_f" ] ; then
	for _i in $(ls "${_f%/}/"*".sh" 2>/dev/null) ; do
	    run_one_test "$_i"
	    if $exit_on_fail && [ $status -ne 0 ] ; then
		break
	    fi
	done
	# No tests found?  Not a tests directory!  Not found...
	[ -n "$status" ] || status=127
    elif [ -f "$_f" ] ; then
	run_one_test "$_f"
    else
	status=127
    fi
}

# Following 2 lines may be modified by installation script
export CTDB_TESTS_ARE_INSTALLED=false
test_dir=$(dirname "$0")

if [ -z "$TEST_VAR_DIR" ] ; then
    if $CTDB_TESTS_ARE_INSTALLED ; then
	TEST_VAR_DIR=$(mktemp -d)
    else
	TEST_VAR_DIR="${test_dir}/var"
    fi
fi
mkdir -p "$TEST_VAR_DIR"

# Must be absolute
TEST_VAR_DIR=$(cd "$TEST_VAR_DIR"; echo "$PWD")
echo "TEST_VAR_DIR=$TEST_VAR_DIR"

if $socket_wrapper ; then
    export SOCKET_WRAPPER_DIR="${TEST_VAR_DIR}/sw"
    mkdir -p "$SOCKET_WRAPPER_DIR"
fi

export TEST_SCRIPTS_DIR="${test_dir}/scripts"

# If no tests specified then run some defaults
if [ -z "$1" ] ; then
    if [ -n "$TEST_LOCAL_DAEMONS" ] ; then
	set -- onnode takeover tool eventscripts simple
    else
	set -- simple complex
    fi
fi

do_cleanup ()
{
    if $TEST_CLEANUP ; then
	echo "Removing TEST_VAR_DIR=$TEST_VAR_DIR"
	rm -rf "$TEST_VAR_DIR"
    else
	echo "Not cleaning up TEST_VAR_DIR=$TEST_VAR_DIR"
    fi
}

cleanup_handler ()
{
    if $TEST_CLEANUP ; then
	if [ -n "$TEST_LOCAL_DAEMONS" -a "$f" = "simple" ] ; then
	    echo "***** shutting down daemons *****"
	    find_and_run_one_test simple/99_daemons_shutdown.sh "$tests_dir"
	fi
    fi
    do_cleanup
}

trap cleanup_handler SIGINT SIGTERM

for f ; do
    find_and_run_one_test "$f"

    if [ $status -eq 127 ] ; then
	# Find the the top-level tests directory
	tests_dir=$(dirname $(cd $TEST_SCRIPTS_DIR; echo $PWD))
	# Strip off current directory from beginning, if there, just
	# to make paths more friendly.
	tests_dir=${tests_dir#$PWD/}
	find_and_run_one_test "$f" "$tests_dir"
    fi

    if [ $status -eq 127 ] ; then
	    die "test \"$f\" is not recognised"
    fi

    if $exit_on_fail && [ $status -ne 0 ] ; then
	    break
    fi
done

rm -f "$tf"

if $with_summary ; then
    echo
    cat "$sf"
    echo
    echo "${tests_passed}/${tests_total} tests passed"
fi

rm -f "$sf"

echo

do_cleanup

if $no_header || $exit_on_fail ; then
    exit $status
elif [ $tests_failed -gt 0 ] ; then
    exit 1
else
    exit 0
fi
