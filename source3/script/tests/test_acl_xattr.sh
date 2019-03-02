#!/bin/sh

# this tests acl_xattr config parameter "ignore system acl"

if [ $# -lt 6 ]; then
cat <<EOF
Usage: $0 SERVER USERNAME PASSWORD PREFIX SMBCLIENT SMBCACLS
EOF
exit 1;
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"
PREFIX="$4"
SMBCLIENT="$5"
SMBCACLS="$6"
shift 6
ADDARGS="$*"
SMBCLIENT="$VALGRIND ${SMBCLIENT} ${ADDARGS}"
SMBCACLS="$VALGRIND ${SMBCACLS} ${ADDARGS}"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

setup_remote_file() {
    local share=$1
    local fname="$share.$$"
    local local_fname=$PREFIX/$fname
    touch $local_fname
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "rm $fname"
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "ls" | grep "$fname" && exit 1
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "lcd $PREFIX; put $fname" || exit 1
}

smbcacls_x() {
    local share=$1
    local fname="$share.$$"

    # skip with SMB1
    echo "$ADDARGS" | grep mNT1 && exit 0

    $SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD "$fname" -x || exit 1
    mxac=$($SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD "$fname" -x | awk '/Maximum access/ {print $3}')

    echo "mxac: $mxac"
    if test "$mxac" != "0x1f01ff" ; then
        exit 1
    fi
}

nt_affects_posix() {
    local share=$1
    local expected=$2
    local b4
    local af
    local fname="$share.$$"
    b4=$($SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "getfacl $fname" 2>/dev/null) || exit 1
    $SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD -a "ACL:$SERVER\force_user:ALLOWED/0x0/READ" 2>/dev/null || exit 1
    af=$($SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "getfacl $fname" 2>/dev/null) || exit 1
    echo "before: $b4"
    echo "after: $af"
    echo "${b4}" | grep -q "^# owner:" || exit 1
    echo "${af}" | grep -q "^# owner:" || exit 1
    if test "$expected" = "true" ; then
        test "$b4" != "$af"
    else
        test "$b4" = "$af"
    fi
}

nt_affects_chown() {
    local share=$1
    local b4_expected
    local af_expected
    local b4_actual
    local af_actual
    local fname="$share.$$"

    echo -n "determining uid of $USERNAME..."
    b4_expected=$(getent passwd $USERNAME) || exit 1
    b4_expected=$(echo "$b4_expected" | awk -F: '{print $3}')
    echo "$b4_expected"

    echo -n "determining uid of force_user..."
    af_expected=$(getent passwd force_user) || exit 1
    af_expected=$(echo "$af_expected" | awk -F: '{print $3}')
    echo "$af_expected"

    #basic sanity...
    test "$b4_expected != $af_expected" || exit 1

    b4_actual=$($SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "getfacl $fname" 2>/dev/null) || exit 1
    echo "${b4_actual}" | grep -q "^# owner:" || exit 1
    b4_actual=$(echo "$b4_actual" | sed -rn 's/^# owner: (.*)/\1/p')
    $SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD -a "ACL:$SERVER\force_user:ALLOWED/0x0/FULL" || exit 1
    $SMBCACLS //$SERVER/$share $fname -U force_user%$PASSWORD -C force_user 2>/dev/null || exit 1
    af_actual=$($SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "getfacl $fname" 2>/dev/null) || exit 1
    echo "${af_actual}" | grep -q "^# owner:" || exit 1
    af_actual=$(echo "$af_actual" | sed -rn 's/^# owner: (.*)/\1/p')
    echo "before: $b4_actual"
    echo "after: $af_actual"
    test "$b4_expected" = "$b4_actual" && test "$af_expected" = "$af_actual"
}

nt_affects_chgrp() {
    local share=$1
    local b4_expected
    local af_expected
    local b4_actual
    local af_actual
    local fname="$share.$$"

    echo -n "determining gid of domusers..."
    b4_expected=$(getent group domusers) || exit 1
    b4_expected=$(echo "$b4_expected" | awk -F: '{print $3}')
    echo "$b4_expected"

    echo -n "determining gid of domadmins..."
    af_expected=$(getent group domadmins) || exit 1
    af_expected=$(echo "$af_expected" | awk -F: '{print $3}')
    echo "$af_expected"

    #basic sanity...
    test "$b4_expected" != "$af_expected" || exit 1

    b4_actual=$($SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "getfacl $fname" 2>/dev/null) || exit 1
    echo "${b4_actual}" | grep -q "^# group:" || exit 1
    b4_actual=$(echo "$b4_actual" | sed -rn 's/^# group: (.*)/\1/p')
    $SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD -G domadmins 2>/dev/null || exit 1
    af_actual=$($SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "getfacl $fname" 2>/dev/null) || exit 1
    echo "${af_actual}" | grep -q "^# group:" || exit 1
    af_actual=$(echo "$af_actual" | sed -rn 's/^# group: (.*)/\1/p')
    echo "before: $b4_actual"
    echo "after: $af_actual"
    test "$af_expected" != "$b4_actual" && test "$af_expected" = "$af_actual"
}

testit "setup remote file tmp" setup_remote_file tmp
testit "setup remote file ign_sysacls" setup_remote_file ign_sysacls
testit "smbcacls -x" smbcacls_x tmp
testit "nt_affects_posix tmp" nt_affects_posix tmp "true"
testit "nt_affects_posix ign_sysacls" nt_affects_posix ign_sysacls "false"
testit "setup remote file tmp" setup_remote_file tmp
testit "setup remote file ign_sysacls" setup_remote_file ign_sysacls
testit "nt_affects_chown tmp" nt_affects_chown tmp
testit "nt_affects_chown ign_sysacls" nt_affects_chown ign_sysacls
testit "setup remote file tmp" setup_remote_file tmp
testit "setup remote file ign_sysacls" setup_remote_file ign_sysacls
testit "nt_affects_chgrp tmp" nt_affects_chgrp tmp
testit "nt_affects_chgrp ign_sysacls" nt_affects_chgrp ign_sysacls
