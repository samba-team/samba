#!/bin/sh
#
# Check smbclient can list a directory containing a fifo.
#

if [ $# -lt 7 ]; then
	cat <<EOF
Usage: $0 SERVER DOMAIN USERNAME PASSWORD PREFIX TARGET_ENV SMBCLIENT
EOF
	exit 1
fi

SERVER=${1}
DOMAIN=${2}
USERNAME=${3}
PASSWORD=${4}
PREFIX=${5}
TARGET_ENV=${6}
SMBCLIENT=${7}
shift 7
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
ADDARGS="$@"

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

# Test that listing a share with a directory containing a fifo succeeds.
#
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=14816
#
test_fifo()
{
	local fifo_dir_path="$PREFIX/$TARGET_ENV/share/fifodir"
	local fifo_path="$fifo_dir_path/fifo_name"

	local tmpfile=$PREFIX/smbclient.in.$$

	cat >$tmpfile <<EOF
cd fifodir
ls
quit
EOF

	# Create fifo directory.
	mkdir -p $fifo_dir_path
	# Create fifo underneath.
	mkfifo $fifo_path

	local cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT //$SERVER/$1 -U$USERNAME%$PASSWORD $ADDARGS < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?

	# Remove fifo and containing dir.
	rm $fifo_path
	rmdir $fifo_dir_path
	rm -f $tmpfile

	# Check for smbclient error.
	if [ $ret != 0 ]; then
		echo "Failed accessing share containing dir with fifo $ret"
		echo "$out"
		return 1
	fi

	# Check for smbclient timeout (server hung).
	echo "$out" | grep 'NT_STATUS_'
	ret=$?
	if [ $ret -eq 0 ]; then
		# Client was disconnected as server timed out.
		echo "$out"
		return 1
	fi

	return 0
}

testit "list directory containing a fifo" \
	test_fifo tmp || failed=$(expr $failed + 1)

exit $failed
