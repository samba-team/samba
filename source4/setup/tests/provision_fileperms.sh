#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: $0 PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

. `dirname $0`/../../../testprogs/blackbox/subunit.sh

# selftest sets the umask to zero. Explicitly set it to 022 here,
# which should mean files should never be writable for anyone else
ORIG_UMASK=`umask`
umask 0022

# checks that the files in the 'private' directory created are not
# world-writable
check_private_file_perms()
{
    target_dir="$1/private"
    result=0

    for file in `ls $target_dir/`
    do
        filepath="$target_dir/$file"

        # skip directories/sockets for now
        if [ ! -f $filepath ] ; then
            continue;
        fi

        # use stat to get the file permissions, i.e. -rw-------
        file_perm=`stat -c "%A" $filepath`

        # then use cut to drop the first 4 chars containing the file type
        # and owner permissions. What's left is the group and other users
        global_perm=`echo $file_perm | cut -c4-`

        # check the remainder doesn't have write permissions set
        if [ -z "${global_perm##*w*}" ] ; then
            echo "Error: $file has $file_perm permissions"
            result=1
        fi
    done
    return $result
}

TARGET_DIR=$PREFIX/basic-dc
rm -rf $TARGET_DIR

# create a dummy smb.conf - we need to use fake ACLs for the file system here
# (but passing --option args with spaces in it proved too difficult in bash)
SMB_CONF=$TARGET_DIR/tmp/smb.conf
mkdir -p `dirname $SMB_CONF`
echo "vfs objects = fake_acls xattr_tdb" > $SMB_CONF

# provision a basic DC
testit "basic-provision" $PYTHON $BINDIR/samba-tool domain provision --server-role="dc" --domain=FOO --realm=foo.example.com --targetdir=$TARGET_DIR --configfile=$SMB_CONF

# check the file permissions in the 'private' directory really are private
testit "provision-fileperms" check_private_file_perms $TARGET_DIR

rm -rf $TARGET_DIR

umask $ORIG_UMASK

exit $failed
