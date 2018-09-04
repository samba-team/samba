#
#  subunit.sh: shell functions to report test status via the subunit protocol.
#  Copyright (C) 2006  Robert Collins <robertc@robertcollins.net>
#  Copyright (C) 2008  Jelmer Vernooij <jelmer@samba.org>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

timestamp() {
  # mark the start time. With Gnu date, you get nanoseconds from %N
  # (here truncated to microseconds with %6N), but not on BSDs,
  # Solaris, etc, which will apparently leave either %N or N at the end.
  date -u +'time: %Y-%m-%d %H:%M:%S.%6NZ' | sed 's/\..*NZ$/.000000Z/'
}

subunit_start_test () {
  # emit the current protocol start-marker for test $1
  timestamp
  printf 'test: %s\n' "$1"
}


subunit_pass_test () {
  # emit the current protocol test passed marker for test $1
  timestamp
  printf 'success: %s\n' "$1"
}

# This is just a hack as we have some broken scripts
# which use "exit $failed", without initializing failed.
failed=0

subunit_fail_test () {
  # emit the current protocol fail-marker for test $1, and emit stdin as
  # the error text.
  # we use stdin because the failure message can be arbitrarily long, and this
  # makes it convenient to write in scripts (using <<END syntax.
  timestamp
  printf 'failure: %s [\n' "$1"
  cat -
  echo "]"
}


subunit_error_test () {
  # emit the current protocol error-marker for test $1, and emit stdin as
  # the error text.
  # we use stdin because the failure message can be arbitrarily long, and this
  # makes it convenient to write in scripts (using <<END syntax.
  timestamp
  printf 'error: %s [\n' "$1"
  cat -
  echo "]"
}

subunit_skip_test () {
  # emit the current protocol skip-marker for test $1, and emit stdin as
  # the error text.
  # we use stdin because the failure message can be arbitrarily long, and this
  # makes it convenient to write in scripts (using <<END syntax.
  printf 'skip: %s [\n' "$1"
  cat -
  echo "]"
}

testit () {
	name="$1"
	shift
	cmdline="$@"
	subunit_start_test "$name"
	output=`$cmdline 2>&1`
	status=$?
	if [ x$status = x0 ]; then
		subunit_pass_test "$name"
	else
		echo "$output" | subunit_fail_test "$name"
	fi
	return $status
}

# This returns 0 if the command gave success and the grep value was found
# all other cases return != 0
testit_grep () {
	name="$1"
	shift
	grep="$1"
	shift
	cmdline="$@"
	subunit_start_test "$name"
	output=`$cmdline 2>&1`
	status=$?
	if [ x$status != x0 ]; then
		printf '%s' "$output" | subunit_fail_test "$name"
		return $status
	fi
	printf '%s' "$output" | grep -q "$grep"
	gstatus=$?
	if [ x$gstatus = x0 ]; then
		subunit_pass_test "$name"
	else
		printf 'GREP: "%s" not found in output:\n%s' "$grep" "$output" | subunit_fail_test "$name"
	fi
	return $status
}

testit_expect_failure () {
	name="$1"
	shift
	cmdline="$@"
	subunit_start_test "$name"
	output=`$cmdline 2>&1`
	status=$?
	if [ x$status = x0 ]; then
		echo "$output" | subunit_fail_test "$name"
	else
		subunit_pass_test "$name"
	fi
	return $status
}

# This returns 0 if the command gave a failure and the grep value was found
# all other cases return != 0
testit_expect_failure_grep () {
	name="$1"
	shift
	grep="$1"
	shift
	cmdline="$@"
	subunit_start_test "$name"
	output=`$cmdline 2>&1`
	status=$?
	if [ x$status = x0 ]; then
		printf '%s' "$output" | subunit_fail_test "$name"
		return 1
	fi
	printf '%s' "$output" | grep -q "$grep"
	gstatus=$?
	if [ x$gstatus = x0 ]; then
		subunit_pass_test "$name"
	else
		printf 'GREP: "%s" not found in output:\n%s' "$grep" "$output" | subunit_fail_test "$name"
	fi
	return $status
}

testok () {
	name=`basename $1`
	failed=$2

	exit $failed
}

# work out the top level source directory
if [ -d source4 ]; then
    SRCDIR="."
else
    SRCDIR=".."
fi
export SRCDIR
