#!/usr/bin/env bash

usage() {
    cat <<EOF
Usage: $0 [OPTIONS] [TESTS]

Options:
  -A		Use "cat -A" to print test output (only some tests)
  -c		Run integration tests on a cluster
  -C		Clean up when done by removing test state directory (see -V)
  -D		Show diff between failed/expected test output (some tests only)
  -e		Exit on the first test failure
  -H		No headers - for running single test with other wrapper
  -I <count>    Iterate tests <count> times, exiting on failure (implies -e, -N)
  -l <count>    Use <count> daemons for local daemon integration tests
  -L            Print daemon logs on test failure (only some tests)
  -N		Don't print summary of tests results after running all tests
  -q		Quiet - don't show tests being run (still displays summary)
  -S <lib>      Use socket wrapper library <lib> for local integration tests
  -v		Verbose - print test output for non-failures (only some tests)
  -V <dir>	Use <dir> as test state directory
  -x		Trace this script with the -x option
  -X		Trace certain scripts run by tests using -x (only some tests)
EOF
    exit 1
}

# Print a message and exit.
die ()
{
    echo "$1" >&2 ; exit "${2:-1}"
}

######################################################################

with_summary=true
quiet=false
exit_on_fail=false
max_iterations=1
no_header=false
test_state_dir=""
cleanup=false
test_time_limit=3600

export CTDB_TEST_VERBOSE=false
export CTDB_TEST_COMMAND_TRACE=false
export CTDB_TEST_CAT_RESULTS_OPTS=""
export CTDB_TEST_DIFF_RESULTS=false
export CTDB_TEST_PRINT_LOGS_ON_ERROR=false
export CTDB_TEST_LOCAL_DAEMONS=3
export CTDB_TEST_SWRAP_SO_PATH=""

while getopts "AcCDehHI:l:LNqS:T:vV:xX?" opt ; do
	case "$opt" in
	A) CTDB_TEST_CAT_RESULTS_OPTS="-A" ;;
	c) CTDB_TEST_LOCAL_DAEMONS="" ;;
	C) cleanup=true ;;
	D) CTDB_TEST_DIFF_RESULTS=true ;;
	e) exit_on_fail=true ;;
	H) no_header=true ;;
	I) max_iterations="$OPTARG" ; exit_on_fail=true ; with_summary=false ;;
	l) CTDB_TEST_LOCAL_DAEMONS="$OPTARG" ;;
	L) CTDB_TEST_PRINT_LOGS_ON_ERROR=true ;;
	N) with_summary=false ;;
	q) quiet=true ;;
	S) CTDB_TEST_SWRAP_SO_PATH="$OPTARG" ;;
	T) test_time_limit="$OPTARG" ;;
	v) CTDB_TEST_VERBOSE=true ;;
	V) test_state_dir="$OPTARG" ;;
	x) set -x ;;
	X) CTDB_TEST_COMMAND_TRACE=true ;;
	\?|h) usage ;;
	esac
done
shift $((OPTIND - 1))

case $(basename "$0") in
    *run_cluster_tests*)
	# Running on a cluster...  same as -c
	CTDB_TEST_LOCAL_DAEMONS=""
	;;
esac

if $quiet ; then
    show_progress() { cat >/dev/null ; }
else
    show_progress() { cat ; }
fi

######################################################################

test_header ()
{
	local name="$1"

	echo "--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--"
	echo "Running test $name ($(date '+%T'))"
	echo "--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--"
}

test_footer ()
{
	local f="$1"
	local status="$2"
	local interp="$3"
	local duration="$4"

	local statstr=""
	if [ "$status" -eq 0 ] ; then
		statstr=""
	else
		statstr=" (status $status)"
	fi

	echo "=========================================================================="
	echo "TEST ${interp}: ${f}${statstr} (duration: ${duration}s)"
	echo "=========================================================================="
}

ctdb_test_run ()
{
	local f="$1"

	$no_header || test_header "$f"

	local status=0
	local start_time

	start_time=$(date '+%s')

	if [ -x "$f" ] ; then
		timeout "$test_time_limit" "$f" </dev/null | show_progress
		status=$?
	else
		echo "TEST IS NOT EXECUTABLE"
		status=99
	fi

	local duration=$(($(date +%s) - start_time))

	tests_total=$((tests_total + 1))

	local interp
	case "$status" in
	0)
		interp="PASSED"
		tests_passed=$((tests_passed + 1))
		;;
	77)
		interp="SKIPPED"
		tests_skipped=$((tests_skipped + 1))
		;;
	99)
		interp="ERROR"
		tests_failed=$((tests_failed + 1))
		;;
	124)
		interp="TIMEDOUT"
		tests_failed=$((tests_failed + 1))
		;;
	*)
		interp="FAILED"
		tests_failed=$((tests_failed + 1))
		;;
	esac

	$no_header || test_footer "$f" "$status" "$interp" "$duration"

	if $with_summary ; then
		local t
		if [ $status -eq 0 ] ; then
			t=" ${interp}"
		else
			t="*${interp}*"
		fi
		printf '%-10s %s\n' "$t" "$f" >>"$summary_file"
	fi

	# Skipped tests should not cause failure
	case "$status" in
	77)
		status=0
		;;
	esac

	return $status
}

######################################################################

tests_total=0
tests_passed=0
tests_skipped=0
tests_failed=0

if ! type mktemp >/dev/null 2>&1 ; then
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
		: >"$t"
	    fi
	)
	echo "$t"
    }
fi

set -o pipefail

run_one_test ()
{
    local f="$1"

    CTDB_TEST_SUITE_DIR=$(dirname "$f")
    export CTDB_TEST_SUITE_DIR
    # This expands the most probable problem cases like "." and "..".
    if [ "$(dirname "$CTDB_TEST_SUITE_DIR")" = "." ] ; then
	    CTDB_TEST_SUITE_DIR=$(cd "$CTDB_TEST_SUITE_DIR" && pwd)
    fi

    # Set CTDB_TEST_TMP_DIR
    #
    # Determine the relative test suite subdirectory.  The top-level
    # test directory needs to be a prefix of the test suite directory,
    # so make absolute versions of both.
    local test_dir test_suite_dir reldir
    test_dir=$(cd "$CTDB_TEST_DIR" && pwd)
    test_suite_dir=$(cd "$CTDB_TEST_SUITE_DIR" && pwd)
    reldir="${test_suite_dir#${test_dir}/}"

    export CTDB_TEST_TMP_DIR="${test_state_dir}/${reldir}"
    rm -rf "$CTDB_TEST_TMP_DIR"
    mkdir -p "$CTDB_TEST_TMP_DIR"

    ctdb_test_run "$f"
    status=$?
}

run_tests ()
{
	local f

	for f ; do
		case "$f" in
		*/README|*/README.md)
			continue
			;;
		esac

		if [ ! -e "$f" ] ; then
			# Can't find it?  Check relative to CTDB_TEST_DIR.
			# Strip off current directory from beginning,
			# if there, just to make paths more friendly.
			f="${CTDB_TEST_DIR#${PWD}/}/${f}"
		fi

		if [ -d "$f" ] ; then
			local test_dir dir reldir subtests

			test_dir=$(cd "$CTDB_TEST_DIR" && pwd)
			dir=$(cd "$f" && pwd)
			reldir="${dir#${test_dir}/}"

			case "$reldir" in
			*/*/*)
				die "test \"$f\" is not recognised"
				;;
			*/*)
				# This is a test suite
				subtests=$(echo "${f%/}/"*".sh")
				if [ "$subtests" = "${f%/}/*.sh" ] ; then
					# Probably empty directory
					die "test \"$f\" is not recognised"
				fi
				;;
			CLUSTER|INTEGRATION|UNIT)
				# A collection of test suites
				subtests=$(echo "${f%/}/"*)
				;;
			*)
				die "test \"$f\" is not recognised"
			esac

			# Recurse - word-splitting wanted
			# shellcheck disable=SC2086
			run_tests $subtests
		elif [ -f "$f" ] ; then
			run_one_test "$f"
		else
			# Time to give up
			die "test \"$f\" is not recognised"
		fi

		if $exit_on_fail && [ $status -ne 0 ] ; then
			return $status
		fi
	done
}

export CTDB_TEST_MODE="yes"

# Following 2 lines may be modified by installation script
CTDB_TESTS_ARE_INSTALLED=false
CTDB_TEST_DIR=$(dirname "$0")
export CTDB_TESTS_ARE_INSTALLED CTDB_TEST_DIR

if [ -z "$test_state_dir" ] ; then
    if $CTDB_TESTS_ARE_INSTALLED ; then
	test_state_dir=$(mktemp -d)
    else
	test_state_dir="${CTDB_TEST_DIR}/var"
    fi
fi
mkdir -p "$test_state_dir"

summary_file="${test_state_dir}/.summary"
: >"$summary_file"

export TEST_SCRIPTS_DIR="${CTDB_TEST_DIR}/scripts"

# If no tests specified then run some defaults
if [ -z "$1" ] ; then
	if [ -n "$CTDB_TEST_LOCAL_DAEMONS" ] ; then
		set -- UNIT INTEGRATION
	else
		set -- INTEGRATION CLUSTER
    fi
fi

do_cleanup ()
{
    if $cleanup ; then
	echo "Removing test state directory: ${test_state_dir}"
	rm -rf "$test_state_dir"
    else
	echo "Not cleaning up test state directory: ${test_state_dir}"
    fi
}

trap "do_cleanup ; exit 130" SIGINT
trap "do_cleanup ; exit 143" SIGTERM

iterations=0
# Special case: -I 0 means iterate forever (until failure)
while [ "$max_iterations" -eq 0 ] || [ $iterations -lt "$max_iterations" ] ; do
	iterations=$((iterations + 1))

	if [ "$max_iterations" -ne 1 ] ; then
		echo
		echo "##################################################"
		echo "ITERATION ${iterations}"
		echo "##################################################"
		echo
	fi

	run_tests "$@"
	status=$?

	if [ $status -ne 0 ] ; then
		break
	fi
done

if $with_summary ; then
	if [ $status -eq 0 ] || ! $exit_on_fail ; then
		echo
		cat "$summary_file"

		echo
		tests_run=$((tests_total - tests_skipped))
		printf '%d/%d tests passed' $tests_passed $tests_run
		if [ $tests_skipped -gt 0 ] ; then
			printf ' (%d skipped)' $tests_skipped
		fi
		printf '\n'
	fi
fi
rm -f "$summary_file"

echo

do_cleanup

if $no_header || $exit_on_fail ; then
    exit $status
elif [ $tests_failed -gt 0 ] ; then
    exit 1
else
    exit 0
fi
