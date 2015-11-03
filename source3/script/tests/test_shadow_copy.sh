#!/bin/bash
#
# Blackbox test for shadow_copy2 VFS.
#

if [ $# -lt 7 ]; then
cat <<EOF
Usage: test_shadow_copy SERVER SERVER_IP DOMAIN USERNAME PASSWORD WORKDIR SMBCLIENT
EOF
exit 1;
fi

SERVER=${1}
SERVER_IP=${2}
DOMAIN=${3}
USERNAME=${4}
PASSWORD=${5}
WORKDIR=${6}
SMBCLIENT=${7}
shift 7
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

SNAPSHOTS[0]='@GMT-2015.10.31-19.40.30'
SNAPSHOTS[1]='@GMT-2016.10.31-19.40.30'
SNAPSHOTS[2]='@GMT-2017.10.31-19.40.30'
SNAPSHOTS[3]='@GMT-2018.10.31-19.40.30'
SNAPSHOTS[4]='@GMT-2019.10.31-19.40.30'
SNAPSHOTS[5]='@GMT-2020.10.31-19.40.30'
SNAPSHOTS[6]='@GMT-2021.10.31-19.40.30'
SNAPSHOTS[7]='@GMT-2022.10.31-19.40.30'
SNAPSHOTS[8]='@GMT-2023.10.31-19.40.30'
SNAPSHOTS[9]='@GMT-2024.10.31-19.40.30'

# build a hierarchy of files, symlinks, and directories
build_files()
{
    local rootdir
    local prefix
    local version
    local destdir
    rootdir=$1
    prefix=$2
    version=$3
    if [ -n "$prefix" ] ; then
        destdir=$rootdir/$prefix
    else
        destdir=$rootdir
    fi

    mkdir -p $destdir
    if [ "$version" = "latest" ] ; then
        #non-snapshot files
        # for non-snapshot version, create legit files
        # so that wide-link checks focus on snapshot files
        touch $destdir/foo
        mkdir -p $destdir/bar
        touch $destdir/bar/baz
        touch $destdir/bar/lfoo
        touch $destdir/bar/letcpasswd
        touch $destdir/bar/loutside
    elif [ "$version" = "fullsnap" ] ; then
        #snapshot files
        touch $destdir/foo
        mkdir -p $destdir/bar
        touch $destdir/bar/baz
        ln -fs ../foo $destdir/bar/lfoo
        ln -fs /etc/passwd $destdir/bar/letcpasswd
        ln -fs ../../outside $destdir/bar/loutside
        touch `dirname $destdir`/outside
    else #subshare snapshot - at bar
        touch $destdir/baz
        ln -fs ../foo $destdir/lfoo
        ln -fs /etc/passwd $destdir/letcpasswd
        ln -fs ../../outside $destdir/loutside
        touch `dirname $destdir`/../outside
    fi

}

# build a snapshots directory
build_snapshots()
{
    local where     #where to build snapshots
    local prefix    #prefix from snapshot dir to share root
    local start     #timestamp index of first snapshot
    local end       #timestamp index of last snapshot
    local sub       #creat a snapshot of subtree of share
    local snapdir
    local snapname
    local i
    local version

    where=$1
    prefix=$2
    start=$3
    end=$4
    sub=$5

    snapdir=$where/.snapshots
    mkdir -p $snapdir

    version="fullsnap"
    if [ "$sub" = "1" ] ; then
        version="subsnap"
        prefix=""

        # a valid link target for an inner symlink -
        # the link is not broken yet should be blocked
        # by wide link checks
        touch $snapdir/foo
    fi

    for i in `seq $start $end` ; do
        snapname=${SNAPSHOTS[$i]}
        mkdir $snapdir/$snapname
        build_files $snapdir/$snapname "$prefix" $version
    done
}

# Test listing previous versions of a file
test_count_versions()
{
    local share
    local path
    local expected_count
    local versions

    share=$1
    path=$2
    expected_count=$3
    versions=`$SMBCLIENT -U$USERNAME%$PASSWORD "//$SERVER/$share" -I $SERVER_IP -c "allinfo $path" | grep "^create_time:" | wc -l`
    if [ "$versions" = "$expected_count" ] ; then
        true
    else
        echo "expected $expected_count versions of $path, got $versions"
        false
    fi
}

# Test fetching a previous version of a file
test_fetch_snap_file()
{
    local share
    local path
    local snapidx

    share=$1
    path=$2
    snapidx=$3
    $SMBCLIENT -U$USERNAME%$PASSWORD "//$SERVER/$share" -I $SERVER_IP \
        -c "get ${SNAPSHOTS[$snapidx]}/$path $WORKDIR/foo"
}

test_shadow_copy_fixed()
{
    local share     #share to contact
    local where     #where to place snapshots
    local prefix    #prefix to files inside snapshot
    local msg
    local allow_wl
    local ncopies_allowd
    local ncopies_blocked

    share=$1
    where=$2
    prefix=$3
    msg=$4
    allow_wl=$5

    ncopies_allowed=4
    ncopies_blocked=1
    if [ -n "$allow_wl" ] ; then
        ncopies_blocked=4
    fi

    #delete snapshots from previous tests
    find $WORKDIR -name ".snapshots" -exec rm -rf {} \; 1>/dev/null 2>&1
    build_snapshots $WORKDIR/$where "$prefix" 0 2

    testit "$msg - regular file" \
        test_count_versions $share foo $ncopies_allowed || \
        failed=`expr $failed + 1`

    testit "$msg - regular file in subdir" \
        test_count_versions $share bar/baz $ncopies_allowed || \
        failed=`expr $failed + 1`

    testit "$msg - local symlink" \
        test_count_versions $share bar/lfoo $ncopies_allowed || \
        failed=`expr $failed + 1`

    testit "$msg - abs symlink outside" \
        test_count_versions $share bar/letcpasswd $ncopies_blocked || \
        failed=`expr $failed + 1`

    testit "$msg - rel symlink outside" \
        test_count_versions $share bar/loutside $ncopies_blocked || \
        failed=`expr $failed + 1`
}

test_shadow_copy_everywhere()
{
    local share     #share to contact

    share=$1

    #delete snapshots from previous tests
    find $WORKDIR -name ".snapshots" -exec rm -rf {} \; 1>/dev/null 2>&1
    build_snapshots "$WORKDIR/mount" "base/share" 0 0
    build_snapshots "$WORKDIR/mount/base" "share" 1 2
    build_snapshots "$WORKDIR/mount/base/share" "" 3 5
    build_snapshots "$WORKDIR/mount/base/share/bar" "" 6 9 1

    testit "snapshots in each dir - regular file" \
        test_count_versions $share foo 4 || \
        failed=`expr $failed + 1`

    testit "snapshots in each dir - regular file in subdir" \
        test_count_versions $share bar/baz 5 || \
        failed=`expr $failed + 1`

    testit "snapshots in each dir - local symlink (but outside snapshot)" \
        test_count_versions $share bar/lfoo 1 || \
        failed=`expr $failed + 1`

    testit "snapshots in each dir - abs symlink outside" \
        test_count_versions $share bar/letcpasswd 1 || \
        failed=`expr $failed + 1`

    testit "snapshots in each dir - rel symlink outside" \
        test_count_versions $share bar/loutside 1 || \
        failed=`expr $failed + 1`

    #the previous versions of the file bar/lfoo points to are outside its
    #snapshot, and are not reachable. However, but previous versions
    #taken at different, non-overlapping times higher up the
    #hierarchy are still reachable.
    testit "fetch a previous version of a regular file" \
        test_fetch_snap_file $share "bar/baz" 6 || \
        failed=`expr $failed + 1`

    testit_expect_failure "fetch a (non-existent) previous version of a symlink" \
        test_fetch_snap_file $share "bar/lfoo" 6 || \
        failed=`expr $failed + 1`

    testit "fetch a previous version of a symlink via browsing (1)" \
        test_fetch_snap_file $share "bar/lfoo" 0 || \
        failed=`expr $failed + 1`

    testit "fetch a previous version of a symlink via browsing (2)" \
        test_fetch_snap_file $share "bar/lfoo" 1 || \
        failed=`expr $failed + 1`

    testit "fetch a previous version of a symlink via browsing (3)" \
        test_fetch_snap_file $share "bar/lfoo" 3 || \
        failed=`expr $failed + 1`

}

#build "latest" files
build_files $WORKDIR/mount base/share "latest"

failed=0

# a test with wide links allowed - also to verify that what's later
# being blocked is a result of server security measures and not
# a testing artifact.
test_shadow_copy_fixed shadow_wl mount base/share "shadow copies with wide links allowed" 1

# tests for a fixed snapshot location
test_shadow_copy_fixed shadow1 mount base/share "full volume snapshots mounted under volume"
test_shadow_copy_fixed shadow2 . base/share "full volume snapshots mounted outside volume"
test_shadow_copy_fixed shadow3 mount/base share "sub volume snapshots mounted under snapshot point"
test_shadow_copy_fixed shadow4 . share "sub volume snapshots mounted outside"
test_shadow_copy_fixed shadow5 mount/base/share "" "full volume snapshots and share mounted under volume"
test_shadow_copy_fixed shadow6 . "" "full volume snapshots and share mounted outside"
test_shadow_copy_fixed shadow8 . share "logical snapshot layout"

# tests for snapshot everywhere - one snapshot location
test_shadow_copy_fixed shadow7 mount base/share "'everywhere' full volume snapshots"
test_shadow_copy_fixed shadow7 mount/base share "'everywhere' sub volume snapshots"
test_shadow_copy_fixed shadow7 mount/base/share "" "'everywhere' share snapshots"

# a test for snapshots everywhere - multiple snapshot locations
test_shadow_copy_everywhere shadow7

exit $failed
