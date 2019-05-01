#!/usr/bin/env bash

usage() {
    cat <<EOF
Usage: $0 [OPTIONS] [TESTS]

Options:
  -A		Use "cat -A" to print test output (only some tests)
  -c		Run integration tests on a cluster
  -C		Remove TEST_VAR_DIR when done
  -d		Print descriptions of tests instead of filenames (dodgy!)
  -D		Show diff between failed/expected test output (some tests only)
  -e		Exit on the first test failure
  -H		No headers - for running single test with other wrapper
  -N		Don't print summary of tests results after running all tests
  -q		Quiet - don't show tests being run (hint: use with -s)
  -S <lib>      Use socket wrapper library <lib> for local integration tests
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

export TEST_VERBOSE=false
export TEST_COMMAND_TRACE=false
export TEST_CAT_RESULTS_OPTS=""
export TEST_DIFF_RESULTS=false
export TEST_LOCAL_DAEMONS
[ -n "$TEST_LOCAL_DAEMONS" ] || TEST_LOCAL_DAEMONS=3
export TEST_VAR_DIR=""
export TEST_CLEANUP=false
export TEST_TIMEOUT=3600
export TEST_SOCKET_WRAPPER_SO_PATH=""

while getopts "AcCdDehHNqS:T:vV:xX?" opt ; do
	case "$opt" in
	A) TEST_CAT_RESULTS_OPTS="-A" ;;
	c) TEST_LOCAL_DAEMONS="" ;;
	C) TEST_CLEANUP=true ;;
	d) with_desc=true ;;  # 4th line of output is description
	D) TEST_DIFF_RESULTS=true ;;
	e) exit_on_fail=true ;;
	H) no_header=true ;;
	N) with_summary=false ;;
	q) quiet=true ;;
	S) TEST_SOCKET_WRAPPER_SO_PATH="$OPTARG" ;;
	T) TEST_TIMEOUT="$OPTARG" ;;
	v) TEST_VERBOSE=true ;;
	V) TEST_VAR_DIR="$OPTARG" ;;
	x) set -x ;;
	X) TEST_COMMAND_TRACE=true ;;
	\?|h) usage ;;
	esac
done
shift $((OPTIND - 1))

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
	elif [ $status -eq 124 ] ; then
	    interp="TIMEOUT"
	    statstr=" (status $status)"
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
    if [ -x "$1" ] ; then
	    timeout $TEST_TIMEOUT "$@" || status=$?
    else
	    echo "TEST IS NOT EXECUTABLE"
	    status=1
    fi

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
	local dir=false
	if [ "$1" = "-d" ] ; then
	    dir=true
	fi
	local t="${TMPDIR:-/tmp}/tmp.$$.$RANDOM"
	(
	    umask 077
	    if $dir ; then
		mkdir "$t"
	    else
		>"$t"
	    fi
	)
	echo "$t"
    }
fi

tf=$(mktemp) || die "mktemp failed for tf - is TMPDIR missing?"
sf=$(mktemp) || die "mktemp failed for sf - is TMPDIR missing?"

set -o pipefail

run_one_test ()
{
    local f="$1"

    tests_total=$(($tests_total + 1))

    ctdb_test_run "$f" | tee "$tf" | show_progress
    status=$?
    if [ $status -eq 0 ] ; then
	tests_passed=$(($tests_passed + 1))
    else
	tests_failed=$(($tests_failed + 1))
    fi
    if $with_summary ; then
	local t
	if [ $status -eq 0 ] ; then
	    t=" PASSED "
	else
	    t="*FAILED*"
	fi
	if $with_desc ; then
	    desc=$(tail -n +4 $tf | head -n 1)
	    f="$desc"
	fi
	echo "$t $f" >>"$sf"
    fi
}

find_and_run_one_test ()
{
    local t="$1"
    local dir="$2"

    local f="${dir}${dir:+/}${t}"

    if [ -d "$f" ] ; then
	local i
	for i in $(ls "${f%/}/"*".sh" 2>/dev/null) ; do
	    run_one_test "$i"
	    if $exit_on_fail && [ $status -ne 0 ] ; then
		break
	    fi
	done
	# No tests found?  Not a tests directory!  Not found...
	[ -n "$status" ] || status=127
    elif [ -f "$f" ] ; then
	run_one_test "$f"
    else
	status=127
    fi
}

export CTDB_TEST_MODE="yes"

# Following 2 lines may be modified by installation script
export CTDB_TESTS_ARE_INSTALLED=false
export CTDB_TEST_DIR=$(dirname "$0")

if [ -z "$TEST_VAR_DIR" ] ; then
    if $CTDB_TESTS_ARE_INSTALLED ; then
	TEST_VAR_DIR=$(mktemp -d)
    else
	TEST_VAR_DIR="${CTDB_TEST_DIR}/var"
    fi
fi
mkdir -p "$TEST_VAR_DIR"

export TEST_SCRIPTS_DIR="${CTDB_TEST_DIR}/scripts"

unit_tests="
	cunit
	eventd
	eventscripts
	onnode
	shellcheck
	takeover
	takeover_helper
	tool
"

# If no tests specified then run some defaults
if [ -z "$1" ] ; then
	if [ -n "$TEST_LOCAL_DAEMONS" ] ; then
		set -- UNIT simple
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

trap "do_cleanup ; exit 130" SIGINT
trap "do_cleanup ; exit 143" SIGTERM

declare -a tests
i=0
for f ; do
	if [ "$f" = "UNIT" ] ; then
		for t in $unit_tests ; do
			tests[i++]="$t"
		done
	else
		tests[i++]="$f"
	fi
done

for f in "${tests[@]}" ; do
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
