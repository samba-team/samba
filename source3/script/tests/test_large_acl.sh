#!/bin/bash
#
# Blackbox test for fetching a large ACL
#

if [ $# -lt 5 ]; then
cat <<EOF
Usage: $0 SERVER USERNAME PASSWORD SMBCLIENT SMBCACLS PARAMS
EOF
exit 1;
fi

SERVER=${1}
USERNAME=${2}
PASSWORD=${3}
SMBCLIENT=${4}
SMBCACLS=${5}
shift 5
ADDARGS="$*"
SMBCLIENT="$VALGRIND ${SMBCLIENT} ${ADDARGS}"
SMBCACLS="$VALGRIND ${SMBCACLS} ${ADDARGS}"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

# build a file to work with
build_files()
{
    touch large_acl
    $SMBCLIENT //$SERVER/acl_xattr_ign_sysacl_windows -U $USERNAME%$PASSWORD -c 'put large_acl' > /dev/null 2>&1
    rm -rf large_acl > /dev/null
}

cleanup()
{
    $SMBCLIENT //$SERVER/acl_xattr_ign_sysacl_windows -U $USERNAME%$PASSWORD -c 'rm large_acl' > /dev/null 2>&1
}

build_files

test_large_acl()
{
    #An ACL with 200 entries, ~7K
    new_acl=$(seq 1001 1200 | sed -r -e '1 i\D:(A;;0x001f01ff;;;WD)' -e 's/(.*)/(A;;0x001f01ff;;;S-1-5-21-11111111-22222222-33333333-\1)/' | tr -d '\n')
    $SMBCACLS //$SERVER/acl_xattr_ign_sysacl_windows -U $USERNAME%$PASSWORD --sddl -S $new_acl large_acl
    actual_acl=$($SMBCACLS //$SERVER/acl_xattr_ign_sysacl_windows -U $USERNAME%$PASSWORD --sddl --numeric large_acl 2>/dev/null | sed -rn 's/.*(D:.*)/\1/p' | tr -d '\n')
    if [ ! "$new_acl" = "$actual_acl" ] ; then
        echo -e "expected:\n$new_acl\nactual:\n$actual_acl\n"
        return 1
    fi
}

failed=0

testit "able to retrieve a large ACL if VFS supports it" test_large_acl || failed=`expr $failed + 1`

cleanup

exit $failed
