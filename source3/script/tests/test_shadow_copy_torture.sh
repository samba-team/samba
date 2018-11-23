#!/bin/bash
#
# Blackbox test for shadow_copy2 VFS.
#

if [ $# -lt 7 ]; then
cat <<EOF
Usage: test_shadow_copy SERVER SERVER_IP DOMAIN USERNAME PASSWORD WORKDIR SMBTORTURE
EOF
exit 1;
fi

SERVER=${1}
SERVER_IP=${2}
DOMAIN=${3}
USERNAME=${4}
PASSWORD=${5}
WORKDIR=${6}
SMBTORTURE="$VALGRIND ${7}"
shift 7

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

SNAPSHOT="@GMT-2015.10.31-19.40.30"

failed=0

# build a hierarchy of files, symlinks, and directories
build_files()
{
    local destdir
    destdir=$1

    echo "$content" > $destdir/foo
}

# build a snapshots directory
build_snapshots()
{
    local snapdir

    snapdir=$WORKDIR/.snapshots

    mkdir -p $snapdir
    mkdir $snapdir/$SNAPSHOT

    build_files $snapdir/$SNAPSHOT
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
	   smb2.twrp.write || \
        failed=`expr $failed + 1`
}

build_files $WORKDIR

# test open for writing and write behaviour of snapshoted files
test_shadow_copy_write "write behaviour of snapshoted files"

exit $failed
