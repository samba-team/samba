#!/bin/sh

# this runs the file serving tests that are expected to pass with samba3

if [ $# -lt 11 ]; then
cat <<EOF
Usage: test_smbclient_s3.sh SERVER SERVER_IP DOMAIN USERNAME PASSWORD USERID LOCAL_PATH PREFIX SMBCLIENT WBINFO NET
EOF
exit 1;
fi

SERVER="${1}"
SERVER_IP="${2}"
DOMAIN="${3}"
USERNAME="${4}"
PASSWORD="${5}"
USERID="${6}"
LOCAL_PATH="${7}"
PREFIX="${8}"
SMBCLIENT="${9}"
WBINFO="${10}"
NET="${11}"
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
WBINFO="$VALGRIND ${WBINFO}"
shift 11
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

# Test that a noninteractive smbclient does not prompt
test_noninteractive_no_prompt()
{
    prompt="smb"

    cmd='echo du | $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`

    if [ $? != 0 ] ; then
	echo "$out"
	echo "command failed"
	false
	return
    fi

    echo "$out" | grep $prompt >/dev/null 2>&1

    if [ $? = 0 ] ; then
	# got a prompt .. fail
	echo matched interactive prompt in non-interactive mode
	false
    else
	true
    fi
}

# Test that an interactive smbclient prompts to stdout
test_interactive_prompt_stdout()
{
    prompt="smb"
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands

    cat > $tmpfile <<EOF
du
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "command failed"
	false
	return
    fi

    echo "$out" | grep $prompt >/dev/null 2>&1

    if [ $? = 0 ] ; then
	# got a prompt .. succeed
	true
    else
	echo failed to match interactive prompt on stdout
	false
    fi
}

# Test creating a bad symlink and deleting it.
test_bad_symlink()
{
    prompt="posix_unlink deleted file /newname"
    tmpfile=$PREFIX/smbclient_bad_symlinks_commands

    cat > $tmpfile <<EOF
posix
posix_unlink newname
symlink badname newname
posix_unlink newname
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed create then delete bad symlink with error $ret"
	false
	return
    fi

    echo "$out" | grep "$prompt" >/dev/null 2>&1

    ret=$?
    if [ $ret = 0 ] ; then
	# got the correct prompt .. succeed
	true
    else
	echo "$out"
	echo "failed create then delete bad symlink - grep failed with $ret"
	false
    fi
}

# Test creating a good symlink and deleting it by path.
test_good_symlink()
{
    tmpfile=$PREFIX/smbclient.in.$$
    slink_name="$LOCAL_PATH/slink"
    slink_target="$LOCAL_PATH/slink_target"

    touch $slink_target
    ln -s $slink_target $slink_name
    cat > $tmpfile <<EOF
del slink
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed delete good symlink with error $ret"
	rm $slink_target
	rm $slink_name
	false
	return
    fi

    if [ ! -e $slink_target ] ; then
	echo "failed delete good symlink - symlink target deleted !"
	rm $slink_target
	rm $slink_name
	false
	return
    fi

    if [ -e $slink_name ] ; then
	echo "failed delete good symlink - symlink still exists"
	rm $slink_target
	rm $slink_name
	false
    else
	# got the correct prompt .. succeed
	rm $slink_target
	true
    fi
}

# Test writing into a read-only directory (logon as guest) fails.
test_read_only_dir()
{
    prompt="NT_STATUS_ACCESS_DENIED making remote directory"
    tmpfile=$PREFIX/smbclient.in.$$

##
## We can't do this as non-root. We always have rights to
## create the directory.
##
    if [ "$USERID" != 0 ] ; then
	echo "skipping test_read_only_dir as non-root"
	true
	return
    fi

##
## We can't do this with an encrypted connection. No credentials
## to set up the channel.
##
    if [ "$ADDARGS" = "-e" ] ; then
	echo "skipping test_read_only_dir with encrypted connection"
	true
	return
    fi

    cat > $tmpfile <<EOF
mkdir a_test_dir
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U% //$SERVER/$1" -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed writing into read-only directory with error $ret"

	false
	return
    fi

    echo "$out" | grep "$prompt" >/dev/null 2>&1

    ret=$?
    if [ $ret = 0 ] ; then
	# got the correct prompt .. succeed
	true
    else
	echo "$out"
	echo "failed writing into read-only directory - grep failed with $ret"
	false
    fi
}


# Test sending a message
test_message()
{
    tmpfile=$PREFIX/message_in.$$

    cat > $tmpfile <<EOF
Test message from pid $$
EOF

    cmd='$SMBCLIENT "$@" -U$USERNAME%$PASSWORD -M $SERVER -p 139 $ADDARGS -n msgtest < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed sending message to $SERVER with error $ret"
	false
	rm -f $tmpfile
	return
    fi

    # The server writes this into a file message.msgtest, via message.%m to test the % sub code
    cmd='$SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmpguest -p 139 $ADDARGS -c "get message.msgtest $PREFIX/message_out.$$" 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed getting sent message from $SERVER with error $ret"
	false
	return
    fi

    if [ cmp $PREFIX/message_out.$$ $tmpfile != 0 ] ; then
	echo "failed comparison of message from $SERVER"
	false
	return
    fi
    true
}

# Test reading an owner-only file (logon as guest) fails.
test_owner_only_file()
{
    prompt="NT_STATUS_ACCESS_DENIED opening remote file"
    tmpfile=$PREFIX/smbclient.in.$$

##
## We can't do this as non-root. We always have rights to
## read the file.
##
    if [ "$USERID" != 0 ] ; then
	echo "skipping test_owner_only_file as non-root"
	true
	return
    fi

##
## We can't do this with an encrypted connection. No credentials
## to set up the channel.
##
    if [ "$ADDARGS" = "-e" ] ; then
	echo "skipping test_owner_only_file with encrypted connection"
	true
	return
    fi

    cat > $tmpfile <<EOF
get unreadable_file
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U% //$SERVER/ro-tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed reading owner-only file with error $ret"
	false
	return
    fi

    echo "$out" | grep "$prompt" >/dev/null 2>&1

    ret=$?
    if [ $ret = 0 ] ; then
	# got the correct prompt .. succeed
	true
    else
	echo "$out"
	echo "failed reading owner-only file - grep failed with $ret"
	false
    fi
}

# Test accessing an msdfs path.
test_msdfs_link()
{
    tmpfile=$PREFIX/smbclient.in.$$
    prompt="  msdfs-target  "

    cat > $tmpfile <<EOF
ls
cd \\msdfs-src1
ls msdfs-target
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/msdfs-share -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed accessing \\msdfs-src1 link with error $ret"
	false
	return
    fi

    echo "$out" | grep "$prompt" >/dev/null 2>&1

    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\msdfs-src1 - grep failed with $ret"
	false
    fi

    cat > $tmpfile <<EOF
ls
cd \\deeppath\\msdfs-src2
ls msdfs-target
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/msdfs-share -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed accessing \\deeppath\\msdfs-src2 link with error $ret"
	false
	return
    fi

    echo "$out" | grep "$prompt" >/dev/null 2>&1

    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\deeppath\\msdfs-src2 - grep failed with $ret"
	false
	return
    else
	true
	return
    fi
}

# Archive bits are correctly set on file/dir creation and rename.
test_rename_archive_bit()
{
    prompt_file="attributes: A (20)"
    prompt_dir="attributes: D (10)"
    tmpfile="$PREFIX/smbclient.in.$$"
    filename="foo.$$"
    filename_ren="bar.$$"
    dirname="foodir.$$"
    dirname_ren="bardir.$$"
    filename_path="$PREFIX/$filename"
    local_name1="$LOCAL_PATH/$filename"
    local_name2="$LOCAL_PATH/$filename_ren"
    local_dir_name1="$LOCAL_PATH/$dirname"
    local_dir_name2="$LOCAL_PATH/$dirname_ren"

    rm -f $filename_path
    rm -f $local_name1
    rm -f $local_name2

# Create a new file, ensure it has 'A' attributes.
    touch $filename_path

    cat > $tmpfile <<EOF
lcd $PREFIX
put $filename
allinfo $filename
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed creating file $filename with error $ret"
	false
	return
    fi

    echo "$out" | grep "$prompt_file" >/dev/null 2>&1

    ret=$?

    rm -f $filename_path
    rm -f $local_name1
    rm -f $local_name2

    if [ $ret = 0 ] ; then
	# got the correct prompt .. succeed
	true
    else
	echo "$out"
	echo "Attributes incorrect on new file $ret"
	false
    fi

# Now check if we remove 'A' and rename, the A comes back.
    touch $filename_path

    cat > $tmpfile <<EOF
lcd $PREFIX
put $filename
setmode $filename -a
ren $filename $filename_ren
allinfo $filename_ren
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed creating file and renaming $filename with error $ret"
	false
	return
    fi

    echo "$out" | grep "$prompt_file" >/dev/null 2>&1

    ret=$?

    rm -f $filename_path
    rm -f $local_name1
    rm -f $local_name2

    if [ $ret = 0 ] ; then
	# got the correct prompt .. succeed
	true
    else
	echo "$out"
	echo "Attributes incorrect on renamed file $ret"
	false
    fi

    rm -rf $local_dir_name1
    rm -rf $local_dir_name2

# Create a new directory, ensure it has 'D' but not 'A' attributes.

    cat > $tmpfile <<EOF
mkdir $dirname
allinfo $dirname
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed creating directory $dirname with error $ret"
	false
	return
    fi

    echo "$out" | grep "$prompt_dir" >/dev/null 2>&1

    ret=$?

    rm -rf $local_dir_name1
    rm -rf $local_dir_name2

    if [ $ret = 0 ] ; then
	# got the correct prompt .. succeed
	true
    else
	echo "$out"
	echo "Attributes incorrect on new directory $ret"
	false
    fi

# Now check if we rename, we still only have 'D' attributes

    cat > $tmpfile <<EOF
mkdir $dirname
ren $dirname $dirname_ren
allinfo $dirname_ren
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed creating directory $dirname and renaming with error $ret"
	false
	return
    fi

    echo "$out" | grep "$prompt_dir" >/dev/null 2>&1

    ret=$?

    rm -f $local_name1
    rm -f $local_name2

    if [ $ret = 0 ] ; then
	# got the correct prompt .. succeed
	true
    else
	echo "$out"
	echo "Attributes incorrect on renamed directory $ret"
	false
    fi
}

# Test authenticating using the winbind ccache
test_ccache_access()
{
    $WBINFO --ccache-save="${USERNAME}%${PASSWORD}"
    ret=$?

    if [ $ret != 0 ] ; then
	echo "wbinfo failed to store creds in cache (user='${USERNAME}', pass='${PASSWORD}')"
	false
	return
    fi

    $SMBCLIENT //$SERVER_IP/tmp -C -U "${USERNAME}" \
	-c quit 2>&1
    ret=$?

    if [ $ret != 0 ] ; then
	echo "smbclient failed to use cached credentials"
	false
	return
    fi

    $WBINFO --ccache-save="${USERNAME}%GarBage"
    ret=$?

    if [ $ret != 0 ] ; then
	echo "wbinfo failed to store creds in cache (user='${USERNAME}', pass='GarBage')"
	false
	return
    fi

    $SMBCLIENT //$SERVER_IP/tmp -C -U "${USERNAME}" \
	-c quit 2>&1
    ret=$?

    if [ $ret -eq 0 ] ; then
	echo "smbclient succeeded with wrong cached credentials"
	false
	return
    fi

    $WBINFO --logoff
}

# Test authenticating using the winbind ccache
test_auth_file()
{
    tmpfile=$PREFIX/smbclient.in.$$
    cat > $tmpfile <<EOF
username=${USERNAME}
password=${PASSWORD}
domain=${DOMAIN}
EOF
    $SMBCLIENT //$SERVER_IP/tmp --authentication-file=$tmpfile \
	-c quit 2>&1
    ret=$?
    rm $tmpfile

    if [ $ret != 0 ] ; then
	echo "smbclient failed to use auth file"
	false
	return
    fi

    cat > $tmpfile <<EOF
username=${USERNAME}
password=xxxx
domain=${DOMAIN}
EOF
    $SMBCLIENT //$SERVER_IP/tmp --authentication-file=$tmpfile\
	-c quit 2>&1
    ret=$?
    rm $tmpfile

    if [ $ret -eq 0 ] ; then
	echo "smbclient succeeded with wrong auth file credentials"
	false
	return
    fi
}

# Test doing a directory listing with backup privilege.
test_backup_privilege_list()
{
    tmpfile=$PREFIX/smbclient_backup_privilege_list

    # If we don't have a DOMAIN component to the username, add it.
    echo "$USERNAME" | grep '\\' 2>&1
    ret=$?
    if [ $ret != 0 ] ; then
	priv_username="$DOMAIN\\$USERNAME"
    else
	priv_username=$USERNAME
    fi

    $NET sam rights grant $priv_username SeBackupPrivilege 2>&1
    ret=$?
    if [ $ret != 0 ] ; then
	echo "Failed to add SeBackupPrivilege to user $priv_username - $ret"
	false
	return
    fi

    cat > $tmpfile <<EOF
backup
ls
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed backup privilege list $ret"
	false
	return
    fi

# Now remove all privileges from this SID.
    $NET sam rights revoke $priv_username SeBackupPrivilege 2>&1
    ret=$?
    if [ $ret != 0 ] ; then
	echo "failed to remove SeBackupPrivilege from user $priv_username - $ret"
	false
	return
    fi
}

# Test accessing an share with bad names (won't convert).
test_bad_names()
{
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/badname-tmp -I $SERVER_IP $ADDARGS -c ls 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed accessing badname-tmp (SMB1) with error $ret"
	false
	return
    fi

    echo "$out" | wc -l 2>&1 | grep 6
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - grep of number of lines (1) failed with $ret"
	false
    fi

    echo "$out" | grep 'Domain=.*OS=.*Server='
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - grep (1) failed with $ret"
	false
    fi

    echo "$out" | grep '^  \. *D'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - grep (2) failed with $ret"
	false
    fi

    echo "$out" | grep '^  \.\. *D'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - grep (3) failed with $ret"
	false
    fi

    echo "$out" | grep '^  blank.txt *N'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - grep (4) failed with $ret"
	false
    fi

    echo "$out" | grep '^ *$'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - grep (5) failed with $ret"
	false
    fi

    echo "$out" | grep 'blocks of size.*blocks available'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - grep (6) failed with $ret"
	false
    fi

    # Now check again with -mSMB3
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/badname-tmp -I $SERVER_IP -mSMB3 $ADDARGS -c ls 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed accessing badname-tmp (SMB3) with error $ret"
	false
	return
    fi

    echo "$out" | wc -l 2>&1 | grep 6
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - SMB3 grep of number of lines (1) failed with $ret"
	false
    fi

    echo "$out" | grep 'Domain=.*OS=.*Server='
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - SMB3 grep (1) failed with $ret"
	false
    fi

    echo "$out" | grep '^  \. *D'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - SMB3 grep (2) failed with $ret"
	false
    fi

    echo "$out" | grep '^  \.\. *D'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - SMB3 grep (3) failed with $ret"
	false
    fi

    echo "$out" | grep '^  blank.txt *N'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - SMB3 grep (4) failed with $ret"
	false
    fi

    echo "$out" | grep '^ *$'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - SMB3 grep (5) failed with $ret"
	false
    fi

    echo "$out" | grep 'blocks of size.*blocks available'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - SMB3 grep (6) failed with $ret"
	false
    fi
}

LOGDIR_PREFIX=test_smbclient_s3

# possibly remove old logdirs:

for OLDDIR in $(find ${PREFIX} -type d -name "${LOGDIR_PREFIX}_*") ;  do
	echo "removing old directory ${OLDDIR}"
	rm -rf ${OLDDIR}
done

LOGDIR=$(mktemp -d ${PREFIX}/${LOGDIR_PREFIX}_XXXXXX)


testit "smbclient -L $SERVER_IP" $SMBCLIENT -L $SERVER_IP -N -p 139 || failed=`expr $failed + 1`
testit "smbclient -L $SERVER -I $SERVER_IP" $SMBCLIENT -L $SERVER -I $SERVER_IP -N -p 139 -c quit || failed=`expr $failed + 1`

testit "noninteractive smbclient does not prompt" \
    test_noninteractive_no_prompt || \
    failed=`expr $failed + 1`

testit "noninteractive smbclient -l does not prompt" \
   test_noninteractive_no_prompt -l $LOGDIR || \
    failed=`expr $failed + 1`

testit "interactive smbclient prompts on stdout" \
   test_interactive_prompt_stdout || \
    failed=`expr $failed + 1`

testit "interactive smbclient -l prompts on stdout" \
   test_interactive_prompt_stdout -l $LOGDIR || \
    failed=`expr $failed + 1`

testit "creating a bad symlink and deleting it" \
   test_bad_symlink || \
   failed=`expr $failed + 1`

testit "creating a good symlink and deleting it by path" \
   test_good_symlink || \
   failed=`expr $failed + 1`

testit "writing into a read-only directory fails" \
   test_read_only_dir ro-tmp || \
   failed=`expr $failed + 1`

testit "writing into a read-only share fails" \
   test_read_only_dir valid-users-tmp || \
   failed=`expr $failed + 1`

testit "Reading a owner-only file fails" \
   test_owner_only_file || \
   failed=`expr $failed + 1`

testit "Accessing an MS-DFS link" \
   test_msdfs_link || \
   failed=`expr $failed + 1`

testit "Ensure archive bit is set correctly on file/dir rename" \
    test_rename_archive_bit || \
    failed=`expr $failed + 1`

testit "ccache access works for smbclient" \
    test_ccache_access || \
    failed=`expr $failed + 1`

testit "sending a message to the remote server" \
    test_message || \
    failed=`expr $failed + 1`

testit "using an authentication file" \
    test_auth_file || \
    failed=`expr $failed + 1`

testit "list with backup privilege" \
    test_backup_privilege_list || \
    failed=`expr $failed + 1`

testit "list a share with bad names (won't convert)" \
    test_bad_names || \
    failed=`expr $failed + 1`

testit "rm -rf $LOGDIR" \
    rm -rf $LOGDIR || \
    failed=`expr $failed + 1`

testok $0 $failed
