#!/usr/bin/env bash
#
# Blackbox test for shadow_copy2 VFS.
#

if [ $# -lt 7 ]; then
	cat <<EOF
Usage: test_shadow_copy SERVER SERVER_IP DOMAIN USERNAME PASSWORD WORKDIR SMBTORTURE SMBCLIENT
EOF
	exit 1
fi

SERVER=${1}
SERVER_IP=${2}
DOMAIN=${3}
USERNAME=${4}
PASSWORD=${5}
WORKDIR=${6}
SMBTORTURE="$VALGRIND ${7}"
SMBCLIENT="$VALGRIND ${8}"
shift 7

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

SNAPSHOT="@GMT-2015.10.31-19.40.30"

failed=0

cd $SELFTEST_TMPDIR || exit 1

# build a hierarchy of files, symlinks, and directories
build_files()
{
	local destdir
	destdir=$1

	echo "$content" >$destdir/foo

	mkdir -p $WORKDIR/subdir/
	touch $WORKDIR/subdir/hardlink
}

# build a snapshots directory
build_snapshots()
{
	local snapdir

	snapdir=$WORKDIR/.snapshots

	mkdir -p $snapdir/$SNAPSHOT

	build_files $snapdir/$SNAPSHOT

	mkdir -p $snapdir/$SNAPSHOT/subdir
	ln "$WORKDIR"/subdir/hardlink "$snapdir"/$SNAPSHOT/subdir/hardlink
}

build_stream_on_snapshot()
{
	file=$WORKDIR/.snapshots/$SNAPSHOT/foo

	setfattr -n 'user.DosStream.bar:$DATA' -v "baz\00" $file || return 1
}

test_shadow_copy_write()
{
	local msg

	msg=$1

	#delete snapshots from previous tests
	find $WORKDIR -name ".snapshots" -exec rm -rf {} \; 1>/dev/null 2>&1
	build_snapshots

	testit "writing to shadow copy of a file" \
		$SMBTORTURE \
		-U$USERNAME%$PASSWORD \
		"//$SERVER/shadow_write" \
		--option="torture:twrp_file=foo" \
		--option="torture:twrp_snapshot=$SNAPSHOT" \
		smb2.twrp.write ||
		failed=$(expr $failed + 1)
}

test_shadow_copy_stream()
{
	local msg

	msg=$1

	#delete snapshots from previous tests
	find $WORKDIR -name ".snapshots" -exec rm -rf {} \; 1>/dev/null 2>&1
	build_snapshots
	build_stream_on_snapshot || {
		subunit_start_test msg
		subunit_skip_test msg <<EOF
test_shadow_copy_stream needs an fs with xattrs
EOF
		return 0
	}

	testit "reading stream of a shadow copy of a file" \
		$SMBTORTURE \
		-U$USERNAME%$PASSWORD \
		"//$SERVER/shadow_write" \
		--option="torture:twrp_file=foo" \
		--option="torture:twrp_stream=bar" \
		--option="torture:twrp_stream_size=3" \
		--option="torture:twrp_snapshot=$SNAPSHOT" \
		smb2.twrp.stream ||
		failed=$(expr $failed + 1)
}

test_shadow_copy_openroot()
{
	local msg

	msg=$1

	#delete snapshots from previous tests
	find $WORKDIR -name ".snapshots" -exec rm -rf {} \; 1>/dev/null 2>&1
	build_snapshots

	testit "opening shadow copy root of share" \
		$SMBTORTURE \
		-U$USERNAME%$PASSWORD \
		"//$SERVER/shadow_write" \
		--option="torture:twrp_snapshot=$SNAPSHOT" \
		smb2.twrp.openroot ||
		failed=$(expr $failed + 1)
}

test_shadow_copy_fix_inodes()
{
	local msg

	msg=$1

	#delete snapshots from previous tests
	find $WORKDIR -name ".snapshots" -exec rm -rf {} \; 1>/dev/null 2>&1
	build_snapshots

	out=$($SMBCLIENT \
		-U $USERNAME%$PASSWORD \
		"//$SERVER/shadow_write" \
		-c "open $SNAPSHOT/subdir/hardlink") || failed=$(expr $failed + 1)
	echo $out
	echo $out | grep "hardlink: for read/write fnum 1" || return 1
}

build_hiddenfile()
{
	local snapdir

	snapdir=$WORKDIR/.snapshots

	#delete snapshots from previous tests
	find $WORKDIR -name ".snapshots" -exec rm -rf {} \; 1>/dev/null 2>&1
	build_snapshots

	touch $WORKDIR/hiddenfile

	# Create a file with hidden attribute
	$SMBCLIENT -U $USERNAME%$PASSWORD \
		"//$SERVER/shadow_write" \
		-c "put $WORKDIR/hiddenfile hiddenfile; setmode hiddenfile +h"
	# ...and move it to the snapshot directory
	mv $WORKDIR/hiddenfile $snapdir/$SNAPSHOT/
}

test_hiddenfile()
{
	build_hiddenfile

	out=$($SMBCLIENT \
		-U $USERNAME%$PASSWORD \
		"//$SERVER/shadow_write" \
		-c "allinfo $SNAPSHOT/hiddenfile") || return 1
	echo $out
	echo $out | grep "attributes: HA (22)" || return 1

	out=$($SMBCLIENT \
		-U $USERNAME%$PASSWORD \
		"//$SERVER/shadow_write" \
		-c "ls $SNAPSHOT/hiddenfile") || return 1
	echo $out
	echo $out | grep "hiddenfile[[:blank:]]*AH" || return 1

	return 0
}

test_shadow_copy_listdir_fix_inodes()
{
	local msg

	msg=$1

	#delete snapshots from previous tests
	find $WORKDIR -name ".snapshots" -exec rm -rf {} \; 1>/dev/null 2>&1
	build_snapshots

	testit "$msg" \
		$SMBTORTURE \
		-U$USERNAME%$PASSWORD \
		"//$SERVER/shadow_write" \
		--option="torture:twrp_snapshot=$SNAPSHOT" \
		smb2.twrp.listdir ||
		failed=$(expr $failed + 1)
}

build_files $WORKDIR

# test open for writing and write behaviour of snapshoted files
test_shadow_copy_write "write behaviour of snapshoted files"

test_shadow_copy_stream "reading stream of snapshotted file"

test_shadow_copy_openroot "opening root of shadow copy share"

testit "fix inodes with hardlink" test_shadow_copy_fix_inodes || failed=$(expr $failed + 1)

testit "Test reading DOS attribute" test_hiddenfile || failed=$(expr $failed + 1)

test_shadow_copy_listdir_fix_inodes "fix inodes when listing directory"

exit $failed
