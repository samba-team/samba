#!/bin/sh

if [ $# -lt 2 ]; then
	cat <<EOF
Usage: $0 VFSTEST PREFIX [OPTIONS]
EOF
	exit 1
fi

TESTBASE=$(cd "$(dirname "$0")" && pwd) || exit 1
VFSTEST=$1
PREFIX=$2
shift 2

incdir="$TESTBASE/../../../../testprogs/blackbox"
. "$incdir/subunit.sh"

VFSTEST_TMPDIR=$(mktemp -d "$PREFIX/vfstest-acl-xattr.XXXXXX") || exit 1
trap 'rm -rf "$VFSTEST_TMPDIR"' 0
cd "$VFSTEST_TMPDIR" || exit 1

test_listxattr()
{
	output=$($VALGRIND "$VFSTEST" -f - "$@" \
		--option="xattr_tdb:file=$VFSTEST_TMPDIR/xattr.tdb" 2>&1 <<'EOF'
load acl_xattr xattr_tdb
connect
open x RC 0600
listxattr x
fsetxattr x user.visible visible
listxattr x
EOF
	)
	status=$?
	if [ "$status" -ne 0 ]; then
		printf '%s\n' "$output"
		return 1
	fi

	# vfstest -f reports command failures without failing the process.
	if printf '%s\n' "$output" |
		grep -Eq '^result was |^command not found:|^Usage:'; then
		printf '%s\n' "$output"
		return 1
	fi

	# The empty list prints nothing. The nonempty list prints user.visible.
	names=$(printf '%s\n' "$output" | grep -E '^(user\.|security\.)')
	if [ "$names" != "user.visible" ]; then
		printf '%s\n' "$output"
		echo "Expected only user.visible in the attribute lists"
		return 1
	fi
	return 0
}

failed=0
testit "acl_xattr_listxattr" test_listxattr "$@" ||
	failed=$(expr "$failed" + 1)

exit "$failed"
