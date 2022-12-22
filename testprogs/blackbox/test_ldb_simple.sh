#!/bin/sh

if [ $# -lt 2 ]; then
	cat <<EOF
Usage: test_ldb_simple.sh PROTOCOL SERVER [OPTIONS]
EOF
	exit 1
fi

p=$1
SERVER=$2
PREFIX=$3
shift 2
options="$*"

. $(dirname $0)/subunit.sh
. "$(dirname "${0}")/common_test_fns.inc"

check()
{
	name="$1"
	shift
	cmdline="$*"
	echo "test: $name"
	$cmdline
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
		failed=$(expr $failed + 1)
	fi
	return $status
}

ldbsearch="${VALGRIND} $(system_or_builddir_binary ldbsearch "${BINDIR}")"

check "currentTime" $ldbsearch $CONFIGURATION $options --basedn='' -H $p://$SERVER --scope=base currentTime || failed=$(expr $failed + 1)

exit $failed
