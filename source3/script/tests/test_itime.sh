#!/bin/sh

# this tests immutable birthtime

if [ $# != 6 ]; then
cat <<EOF
Usage: $0 SERVER USERNAME PASSWORD LOCAL_PATH SMBCLIENT SHARE
EOF
exit 1
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"
LOCAL_PATH="$4"
SMBCLIENT="$5"
SHARE="$6"
SAMBATOOL="$BINDIR/samba-tool"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

# Show that setting DOS attributes on a locally created file, therefore lacking
# a DOS xattr and an itime, doesn't set an itime
no_itime_on_local_file() {
    fname="tmp.$$"
    local_fname="$LOCAL_PATH/$fname"
    touch $local_fname || return 1

    $SMBCLIENT //$SERVER/$SHARE -U $USERNAME%$PASSWORD -c "setmode $fname +h" || return 1

    dosinfo=$($SAMBATOOL ntacl getdosinfo $local_fname) || return 1
    echo $dosinfo | grep -q "xattr_DosInfo4" || return 1
    echo $dosinfo | grep -q "1: XATTR_DOSINFO_ATTRIB" || return 1
    echo $dosinfo | grep -q "1: XATTR_DOSINFO_CREATE_TIME" || return 1
    echo $dosinfo | grep -q "0: XATTR_DOSINFO_ITIME" || return 1
}

testit "no_itime_on_local_file" no_itime_on_local_file
