#!/bin/sh

# this runs the file serving tests that are expected to pass with samba3

if [ $# -lt 13 ]; then
cat <<EOF
Usage: test_smbclient_s3.sh SERVER SERVER_IP DOMAIN USERNAME PASSWORD USERID LOCAL_PATH PREFIX SMBCLIENT WBINFO NET CONFIGURATION PROTOCOL
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
CONFIGURATION="${12}"
PROTOCOL="${13}"
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
WBINFO="$VALGRIND ${WBINFO}"
shift 13
RAWARGS="${CONFIGURATION} -m${PROTOCOL}"
ADDARGS="${RAWARGS} $*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

# Do not let deprecated option warnings muck this up
SAMBA_DEPRECATED_SUPPRESS=1
export SAMBA_DEPRECATED_SUPPRESS

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
	return 1
    fi

    echo "$out" | grep $prompt >/dev/null 2>&1

    if [ $? = 0 ] ; then
	# got a prompt .. fail
	echo matched interactive prompt in non-interactive mode
	return 1
    fi

    return 0
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
	return 1
    fi

    echo "$out" | grep $prompt >/dev/null 2>&1

    if [ $? != 0 ] ; then
	echo failed to match interactive prompt on stdout
	return 1
    fi

    return 0
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
	return 1
    fi

    echo "$out" | grep "$prompt" >/dev/null 2>&1

    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed create then delete bad symlink - grep failed with $ret"
	return 1
    fi

    return 0
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
	return 1
    fi

    if [ ! -e $slink_target ] ; then
	echo "failed delete good symlink - symlink target deleted !"
	rm $slink_target
	rm $slink_name
	return 1
    fi

    if [ -e $slink_name ] ; then
	echo "failed delete good symlink - symlink still exists"
	rm $slink_target
	rm $slink_name
	return 1
    fi

    rm $slink_target
    return 0
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
	return 0
    fi

##
## We can't do this with an encrypted connection. No credentials
## to set up the channel.
##
    if [ "$ADDARGS" = "-e" ] ; then
	echo "skipping test_read_only_dir with encrypted connection"
	return 0
    fi

    cat > $tmpfile <<EOF
mkdir a_test_dir
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U% "//$SERVER/$1" -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed writing into read-only directory with error $ret"

	return 1
    fi

    echo "$out" | grep "$prompt" >/dev/null 2>&1

    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed writing into read-only directory - grep failed with $ret"
	return 1
    fi

    return 0
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
	rm -f $tmpfile
	return 1
    fi

    # The server writes this into a file message.msgtest, via message.%m to test the % sub code
    cmd='$SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmpguest -p 139 $ADDARGS -c "get message.msgtest $PREFIX/message_out.$$" 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed getting sent message from $SERVER with error $ret"
	return 1
    fi

    if [ cmp $PREFIX/message_out.$$ $tmpfile != 0 ] ; then
	echo "failed comparison of message from $SERVER"
	return 1
    fi

    return 0
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
	return 0
    fi

##
## We can't do this with an encrypted connection. No credentials
## to set up the channel.
##
    if [ "$ADDARGS" = "-e" ] ; then
	echo "skipping test_owner_only_file with encrypted connection"
	return 0
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
	return 1
    fi

    echo "$out" | grep "$prompt" >/dev/null 2>&1

    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed reading owner-only file - grep failed with $ret"
	return 1
    fi

    return 0
}

# Test accessing an msdfs path.
test_msdfs_link()
{
    tmpfile=$PREFIX/smbclient.in.$$
    prompt="  msdfs-target  "

    cmd='$SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/msdfs-share -I $SERVER_IP $ADDARGS -m $PROTOCOL -c dir 2>&1'
    out=`eval $cmd`
    ret=$?

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing msfds-share\ with error $ret"
	return 1
    fi

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
	return 1
    fi

    echo "$out" | grep "$prompt" >/dev/null 2>&1

    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\msdfs-src1 - grep failed with $ret"
	return 1
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
	return 1
    fi

    echo "$out" | grep "$prompt" >/dev/null 2>&1

    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\deeppath\\msdfs-src2 - grep failed with $ret"
	return 1
    fi

    return 0
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
	return 1
    fi

    echo "$out" | grep "$prompt_file" >/dev/null 2>&1

    ret=$?

    rm -f $filename_path
    rm -f $local_name1
    rm -f $local_name2

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "Attributes incorrect on new file $ret"
	return 1
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
	return 1
    fi

    echo "$out" | grep "$prompt_file" >/dev/null 2>&1

    ret=$?

    rm -f $filename_path
    rm -f $local_name1
    rm -f $local_name2

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "Attributes incorrect on renamed file $ret"
	return 1
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
	return 1
    fi

    echo "$out" | grep "$prompt_dir" >/dev/null 2>&1

    ret=$?

    rm -rf $local_dir_name1
    rm -rf $local_dir_name2

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "Attributes incorrect on new directory $ret"
	return 1
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
	return 1
    fi

    echo "$out" | grep "$prompt_dir" >/dev/null 2>&1

    ret=$?

    rm -f $local_name1
    rm -f $local_name2

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "Attributes incorrect on renamed directory $ret"
	return 1
    fi

    return 0
}

# Test authenticating using the winbind ccache
test_ccache_access()
{
    $WBINFO --ccache-save="${USERNAME}%${PASSWORD}"
    ret=$?

    if [ $ret != 0 ] ; then
	echo "wbinfo failed to store creds in cache (user='${USERNAME}', pass='${PASSWORD}')"
	return 1
    fi

    $SMBCLIENT //$SERVER_IP/tmp -C -U "${USERNAME}" $ADDARGS -c quit 2>&1
    ret=$?

    if [ $ret != 0 ] ; then
	echo "smbclient failed to use cached credentials"
	return 1
    fi

    $WBINFO --ccache-save="${USERNAME}%GarBage"
    ret=$?

    if [ $ret != 0 ] ; then
	echo "wbinfo failed to store creds in cache (user='${USERNAME}', pass='GarBage')"
	return 1
    fi

    $SMBCLIENT //$SERVER_IP/tmp -C -U "${USERNAME}" $ADDARGS -c quit 2>&1
    ret=$?

    if [ $ret -eq 0 ] ; then
	echo "smbclient succeeded with wrong cached credentials"
	return 1
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
    $SMBCLIENT //$SERVER_IP/tmp --authentication-file=$tmpfile $ADDARGS -c quit 2>&1
    ret=$?
    rm $tmpfile

    if [ $ret != 0 ] ; then
	echo "smbclient failed to use auth file"
	return 1
    fi

    cat > $tmpfile <<EOF
username=${USERNAME}
password=xxxx
domain=${DOMAIN}
EOF
    $SMBCLIENT //$SERVER_IP/tmp --authentication-file=$tmpfile $ADDARGS -c quit 2>&1
    ret=$?
    rm $tmpfile

    if [ $ret -eq 0 ] ; then
	echo "smbclient succeeded with wrong auth file credentials"
	return 1
    fi
}

# Test doing a directory listing with backup privilege.
test_backup_privilege_list()
{
    tmpfile=$PREFIX/smbclient_backup_privilege_list

    # selftest uses the forward slash as a separator, but "net sam rights
    # grant" requires the backslash separator
    USER_TMP=$(printf '%s' "$USERNAME" | tr '/' '\\')

    # If we don't have a DOMAIN component to the username, add it.
    printf '%s' "$USER_TMP" | grep '\\' 2>&1
    ret=$?
    if [ $ret != 0 ] ; then
	priv_username="$DOMAIN\\$USER_TMP"
    else
	priv_username="$USER_TMP"
    fi

    $NET sam rights grant $priv_username SeBackupPrivilege 2>&1
    ret=$?
    if [ $ret != 0 ] ; then
	echo "Failed to add SeBackupPrivilege to user $priv_username - $ret"
	return 1
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
	return 1
    fi

# Now remove all privileges from this SID.
    $NET sam rights revoke $priv_username SeBackupPrivilege 2>&1
    ret=$?
    if [ $ret != 0 ] ; then
	echo "failed to remove SeBackupPrivilege from user $priv_username - $ret"
	return 1
    fi
}

# Test accessing an share with bad names (won't convert).
test_bad_names()
{
    # First with SMB1

if [ $PROTOCOL = "NT1" ]; then
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/badname-tmp -I $SERVER_IP $ADDARGS -m$PROTOCOL -c ls 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed accessing badname-tmp (SMB1) with error $ret"
	return 1
    fi

    echo "$out" | wc -l 2>&1 | grep 5
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - grep of number of lines (1) failed with $ret"
	return 1
    fi

    echo "$out" | grep '^  \. *D'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - grep (1) failed with $ret"
	return 1
    fi

    echo "$out" | grep '^  \.\. *D'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - grep (2) failed with $ret"
	return 1
    fi

    echo "$out" | grep '^  blank.txt *N'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - grep (3) failed with $ret"
	return 1
    fi

    echo "$out" | grep '^ *$'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - grep (4) failed with $ret"
	return 1
    fi

    echo "$out" | grep 'blocks of size.*blocks available'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - grep (5) failed with $ret"
	return 1
    fi
fi

if [ $PROTOCOL = "SMB3" ]; then

    # Now check again with -mSMB3
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/badname-tmp -I $SERVER_IP $ADDARGS -m$PROTOCOL -c ls 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed accessing badname-tmp (SMB3) with error $ret"
	return 1
    fi

    echo "$out" | wc -l 2>&1 | grep 5
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - SMB3 grep of number of lines (1) failed with $ret"
	return 1
    fi

    echo "$out" | grep '^  \. *D'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - SMB3 grep (1) failed with $ret"
	return 1
    fi

    echo "$out" | grep '^  \.\. *D'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - SMB3 grep (2) failed with $ret"
	return 1
    fi

    echo "$out" | grep '^  blank.txt *N'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - SMB3 grep (3) failed with $ret"
	return 1
    fi

    echo "$out" | grep '^ *$'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - SMB3 grep (4) failed with $ret"
	return 1
    fi

    echo "$out" | grep 'blocks of size.*blocks available'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed listing \\badname-tmp - SMB3 grep (5) failed with $ret"
	return 1
    fi
fi
}

# Test accessing an share with a name that must be mangled - with acl_xattrs.
# We know foo:bar gets mangled to FF4GBY~Q with the default name-mangling algorithm (hash2).
test_mangled_names()
{
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    cat > $tmpfile <<EOF
ls
cd FF4GBY~Q
ls
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/manglenames_share -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed accessing manglenames_share with error $ret"
	return 1
    fi

    echo "$out" | grep 'NT_STATUS'
    ret=$?
    if [ $ret = 0 ] ; then
	echo "$out"
	echo "failed - NT_STATUS_XXXX listing \\manglenames_share\\FF4GBY~Q"
	return 1
    fi
}

# Test using scopy to copy a file on the server.
test_scopy()
{
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    scopy_file=$PREFIX/scopy_file

    rm -f $scopy_file
    cat > $tmpfile <<EOF
put ${SMBCLIENT}
scopy smbclient scopy_file
lcd ${PREFIX}
get scopy_file
del smbclient
del scopy_file
quit
EOF
if [ $PROTOCOL = "SMB3" ]; then
    # First SMB3
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS -m$PROTOOCL < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    out1=`md5sum ${SMBCLIENT} | sed -e 's/ .*//'`
    out2=`md5sum ${scopy_file} | sed -e 's/ .*//'`
    rm -f $tmpfile
    rm -f $scopy_file

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed scopy test (1) with output $ret"
	return 1
    fi

    if [ $out1 != $out2 ] ; then
	echo "$out1 $out2"
	echo "failed md5sum (1)"
	return 1
    fi
fi
#
# Now do again using SMB1
# to force client-side fallback.
#

if [ $PROTOCOL = "NT1" ]; then
    cat > $tmpfile <<EOF
put ${SMBCLIENT}
scopy smbclient scopy_file
lcd ${PREFIX}
get scopy_file
del smbclient
del scopy_file
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS -m$PROTOCOL < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    out1=`md5sum ${SMBCLIENT} | sed -e 's/ .*//'`
    out2=`md5sum ${scopy_file} | sed -e 's/ .*//'`
    rm -f $tmpfile
    rm -f $scopy_file

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed scopy test (2) with output $ret"
	return 1
    fi

    if [ $out1 != $out2 ] ; then
	echo "$out1 $out2"
	echo "failed md5sum (2)"
	return 1
    fi
fi
}

# Test creating a stream on the root of the share directory filname - :foobar
test_toplevel_stream()
{
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    cat > $tmpfile <<EOF
put ${PREFIX}/smbclient_interactive_prompt_commands :foobar
allinfo \\
setmode \\ -a
quit
EOF
    # Only with SMB3???
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS -mSMB3 < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed creating toplevel stream :foobar with error $ret"
	return 1
    fi

    echo "$out" | grep '^stream:.*:foobar'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed creating toplevel stream :foobar"
	return 1
    fi
}

# Test wide links are restricted.
test_widelinks()
{
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    cat > $tmpfile <<EOF
cd dot
ls
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/widelinks_share -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed accessing widelinks_share with error $ret"
	return 1
    fi

    echo "$out" | grep 'NT_STATUS'
    ret=$?
    if [ $ret = 0 ] ; then
	echo "$out"
	echo "failed - NT_STATUS_XXXX listing \\widelinks_share\\dot"
	return 1
    fi

    cat > $tmpfile <<EOF
allinfo source
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/widelinks_share -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed accessing widelinks_share with error $ret"
	return 1
    fi

# This should fail with NT_STATUS_ACCESS_DENIED
    echo "$out" | grep 'NT_STATUS_ACCESS_DENIED'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed - should get NT_STATUS_ACCESS_DENIED listing \\widelinks_share\\source"
	return 1
    fi
}

# Test creating then deleting a stream file doesn't leave a lost-XXXXX directory.
test_streams_depot_delete()
{
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    rm -rf "$LOCAL_PATH/lost-*"

    cat > $tmpfile <<EOF
put ${PREFIX}/smbclient_interactive_prompt_commands foo:bar
del foo
ls lost*
quit
EOF
    # This only works with SMB3?
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS -mSMB3 < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed creating then deleting foo:bar with error $ret"
	return 1
    fi

    echo "$out" | grep 'NT_STATUS_NO_SUCH_FILE listing \\lost\*'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "deleting foo:bar left lost-XXX directory"
	rm -rf "$LOCAL_PATH/lost-*"
	return 1
    fi
}

# Test follow symlinks can't access symlinks
test_nosymlinks()
{
# Setup test dirs.
    local_test_dir="$LOCAL_PATH/nosymlinks/test"
    local_slink_name="$local_test_dir/source"
    local_slink_target="$local_test_dir/nosymlink_target_file"

    share_test_dir="test"
    share_foo_dir="$share_test_dir/foo"
    share_foobar_dir="$share_test_dir/foo/bar"
    share_target_file="$share_test_dir/foo/bar/testfile"

    rm -rf $local_test_dir

    local_nosymlink_target_file="nosymlink_target_file"
    echo "$local_slink_target" > $local_nosymlink_target_file

    local_foobar_target_file="testfile"
    echo "$share_target_file" > $local_foobar_target_file

    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    cat > $tmpfile <<EOF
mkdir $share_test_dir
mkdir $share_foo_dir
mkdir $share_foobar_dir
cd /$share_test_dir
put $local_nosymlink_target_file
cd /$share_foobar_dir
put $local_foobar_target_file
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/nosymlinks -I $SERVER_IP $LOCAL_ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile
    rm -f $local_nosymlink_target_file
    rm -f $local_foobar_target_file

    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed accessing local_symlinks with error $ret"
       false
       return
    fi

    echo "$out" | grep 'NT_STATUS_'
    ret=$?
    if [ $ret -eq 0 ] ; then
       echo "$out"
       echo "failed - got an NT_STATUS error"
       false
       return
    fi

# Create the symlink locally
    ln -s $local_slink_target $local_slink_name

# Getting a file through a symlink name should fail.
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    cat > $tmpfile <<EOF
get test\\source
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/nosymlinks -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed accessing nosymlinks with error $ret"
       return 1
    fi

    echo "$out" | grep 'NT_STATUS_ACCESS_DENIED'
    ret=$?
    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed - should get NT_STATUS_ACCESS_DENIED getting \\nosymlinks\\source"
       return 1
    fi

# But we should be able to create and delete directories.
    cat > $tmpfile <<EOF
mkdir test\\a
mkdir test\\a\\b
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/nosymlinks -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed accessing nosymlinks with error $ret"
       return 1
    fi

    echo "$out" | grep 'NT_STATUS'
    ret=$?
    if [ $ret -eq 0 ] ; then
	echo "$out"
	echo "failed - NT_STATUS_XXXX doing mkdir a; mkdir a\\b on \\nosymlinks"
	return 1
    fi

# Ensure regular file/directory access also works.
    cat > $tmpfile <<EOF
cd test\\foo\\bar
ls
get testfile -
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/nosymlinks -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed accessing nosymlinks with error $ret"
       return 1
    fi

    echo "$out" | grep 'NT_STATUS'
    ret=$?
    if [ $ret -eq 0 ] ; then
       echo "$out"
       echo "failed - NT_STATUS_XXXX doing cd foo\\bar; get testfile on \\nosymlinks"
       return 1
    fi

# CLEANUP
    rm -f $local_slink_name

    cat > $tmpfile <<EOF
deltree test
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/nosymlinks -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed accessing nosymlinks with error $ret"
       return 1
    fi

    echo "$out" | grep 'NT_STATUS'
    ret=$?
    if [ $ret -eq 0 ] ; then
       echo "$out"
       echo "failed - NT_STATUS_XXXX doing cd foo\\bar; get testfile on \\nosymlinks"
       return 1
    fi
}

# Test we can follow normal symlinks.
# Bug: https://bugzilla.samba.org/show_bug.cgi?id=12860
# Note - this needs to be tested over SMB3, not SMB1.

test_local_symlinks()
{
# Setup test dirs.
    LOCAL_RAWARGS="${CONFIGURATION} -mSMB3"
    LOCAL_ADDARGS="${LOCAL_RAWARGS} $*"

    share_test_dir="test"
    share_slink_target_dir="$share_test_dir/dir1"

    local_test_dir="$LOCAL_PATH/local_symlinks/$share_test_dir"
    local_slink_name="$local_test_dir/sym_name"
    local_slink_target_dir="$local_test_dir/dir1"

    rm -rf $local_test_dir

# Create the initial directories
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    cat > $tmpfile <<EOF
mkdir $share_test_dir
mkdir $share_slink_target_dir
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/local_symlinks -I $SERVER_IP $LOCAL_ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed accessing local_symlinks with error $ret"
       false
       return
    fi

    echo "$out" | grep 'NT_STATUS_'
    ret=$?
    if [ $ret -eq 0 ] ; then
       echo "$out"
       echo "failed - got an NT_STATUS error"
       false
       return
    fi

# Create the symlink locally
    ln -s $local_slink_target_dir $local_slink_name
    ret=$?
    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed - unable to create symlink"
       ls -la $local_test_dir
       false
       return
    fi

# Can we cd into the symlink name and ls ?
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    cat > $tmpfile <<EOF
cd $share_test_dir\\sym_name
ls
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/local_symlinks -I $SERVER_IP $LOCAL_ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed accessing local_symlinks with error $ret"
       false
       return
    fi

    echo "$out" | grep 'NT_STATUS_'
    ret=$?
    if [ $ret -eq 0 ] ; then
       echo "$out"
       echo "failed - got an NT_STATUS error"
       false
       return
    fi

# CLEANUP
    rm -f $local_slink_name

    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    cat > $tmpfile <<EOF
deltree $share_test_dir
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/local_symlinks -I $SERVER_IP $LOCAL_ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed accessing local_symlinks with error $ret"
       false
       return
    fi

    echo "$out" | grep 'NT_STATUS_'
    ret=$?
    if [ $ret -eq 0 ] ; then
       echo "$out"
       echo "failed - got an NT_STATUS error"
       false
       return
    fi
}

#
# Regression test for CVE-2019-10197
# we should always get ACCESS_DENIED
#
test_noperm_share_regression()
{
    cmd='$SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/noperm -I $SERVER_IP $LOCAL_ADDARGS -c "ls;ls"  2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    if [ $ret -eq 0 ] ; then
       echo "$out"
       echo "failed accessing no perm share should not work"
       return 1
    fi

    num=`echo "$out" | grep 'NT_STATUS_ACCESS_DENIED' | wc -l`
    if [ "$num" -ne "2" ] ; then
       echo "$out"
       echo "failed num[$num] - two NT_STATUS_ACCESS_DENIED lines expected"
       return 1
    fi

    return 0
}

# Test smbclient deltree command
test_deltree()
{
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    deltree_dir=$PREFIX/deltree_dir

    rm -rf $deltree_dir
    cat > $tmpfile <<EOF
mkdir deltree_dir
mkdir deltree_dir/foo
mkdir deltree_dir/foo/bar
put ${SMBCLIENT} deltree_dir/foo/bar/client
deltree deltree_dir
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed deltree test with output $ret"
	false
	return
    fi

    echo "$out" | grep 'NT_STATUS_'
    ret=$?
    if [ $ret -eq 0 ] ; then
       echo "$out"
       echo "failed - got an NT_STATUS error"
       false
       return
    fi

    if [ -d $deltree_dir ] ; then
	echo "deltree did not delete everything"
	false
	return
    fi
}

# Test smbclient setmode command
test_setmode()
{
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands

    cat > $tmpfile <<EOF
del test_setmode
put ${SMBCLIENT} test_setmode
setmode test_setmode +r +s +h +a
allinfo test_setmode
setmode test_setmode -rsha
allinfo test_setmode
del test_setmode
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed setmode test with output $ret"
	false
	return
    fi

    echo "$out" | grep 'attributes: RHSA'
    ret=$?
    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed - should get attributes: RHSA"
       false
       return
    fi

    echo "$out" | grep 'attributes:  (80)'
    ret=$?
    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed - should also get attributes:  (80)"
       false
       return
    fi
}

# Test smbclient utimes command
test_utimes()
{
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands

    saved_TZ="$TZ"
    TZ=UTC
    export TZ
    saved_LANG="$LANG"
    LANG=C
    export LANG

    cat > $tmpfile <<EOF
del utimes_test
put ${SMBCLIENT} utimes_test
allinfo utimes_test
utimes utimes_test 2016:02:04-06:19:20 17:01:01-05:10:20 -1 -1
allinfo utimes_test
del utimes_test
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?

    if [ -n "$saved_TZ" ] ; then
	export TZ="$saved_TZ"
    else
	unset TZ
    fi
    if [ -n "$saved_LANG" ] ; then
	export LANG="$saved_LANG"
    else
	unset LANG
    fi

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed utimes test with output $ret"
	false
	return
    fi

    # Now, we should have 2 identical write_time and change_time
    # values, but one access_time of Jan  1 05:10:20 AM,
    # and one create_time of Feb 04 06:19:20 AM 2016
    out_sorted=`echo "$out" | sort | uniq`
    num_create=`echo "$out_sorted" | grep -c 'create_time:'`
    num_access=`echo "$out_sorted" | grep -c 'access_time:'`
    num_write=`echo "$out_sorted" | grep -c 'write_time:'`
    num_change=`echo "$out_sorted" | grep -c 'change_time:'`
    if [ "$num_create" != "2" ]; then
        echo "failed - should get two create_time $out"
        false
        return
    fi
    if [ "$num_access" != "2" ]; then
        echo "failed - should get two access_time $out"
        false
        return
    fi
    if [ "$num_write" != "1" ]; then
        echo "failed - should only get one write_time $out"
        false
        return
    fi
    if [ "$num_change" != "1" ]; then
        echo "failed - should only get one change_time $out"
        false
        return
    fi

    # This could be: Sun Jan  1 05:10:20 AM 2017
    # or           : Sun Jan  1 05:10:20 2017 CET
    echo "$out" | grep 'access_time:.*Sun Jan.*1 05:10:20 .*2017.*'
    ret=$?
    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo
       echo "failed - should get access_time:    Sun Jan  1 05:10:20 [AM] 2017"
       false
       return
    fi

    # This could be: Thu Feb  4 06:19:20 AM 2016
    # or           : Thu Feb  4 06:19:20 2016 CET
    echo "$out" | grep 'create_time:.*Thu Feb.*4 06:19:20 .*2016.*'
    ret=$?
    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo
       echo "failed - should get access_time:    Thu Feb  4 06:19:20 [AM] 2016"
       false
       return
    fi
}

# Test smbclient renames with pathnames containing '..'
test_rename_dotdot()
{
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands

    cat > $tmpfile <<EOF
deltree dotdot_test
mkdir dotdot_test
cd dotdot_test
mkdir dir1
mkdir dir2
cd dir1
put ${SMBCLIENT} README
rename README ..\\dir2\\README
cd ..
cd dir2
allinfo README
cd \\
deltree dotdot_test
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed rename_dotdot test with output $ret"
	false
	return
    fi

    # We are allowed to get NT_STATUS_NO_SUCH_FILE listing \dotdot_test
    # as the top level directory should not exist, but no other errors.

    error_str=`echo $out | grep NT_STATUS | grep -v "NT_STATUS_NO_SUCH_FILE listing .dotdot_test"`
    if [ "$error_str" != "" ]; then
        echo "failed - unexpected NT_STATUS error in $out"
        false
        return
    fi
}

# Test doing a volume command.
test_volume()
{
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    cat > $tmpfile <<EOF
volume
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed doing volume command with error $ret"
	return 1
    fi

    echo "$out" | grep '^Volume: |tmp| serial number'
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed doing volume command"
	return 1
    fi
}

test_server_os_message()
{
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    cat > $tmpfile <<EOF
ls
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed to connect error $ret"
       return 1
    fi

    echo "$out" | grep 'Try "help" to get a list of possible commands.'
    ret=$?
    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo 'failed - should get: Try "help" to get a list of possible commands.'
       return 1
    fi

    return 0
}

test_server_quiet_message()
{
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    cat > $tmpfile <<EOF
ls
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS --quiet < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed to connect error $ret"
       return 1
    fi

    echo "$out" | grep 'Try "help" to get a list of possible commands.'
    ret=$?
    if [ $ret -eq 0 ] ; then
       echo "$out"
       echo 'failed - quiet should skip this message.'
       return 1
    fi

    return 0
}

# Test xattr_stream correctly reports mode.
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=13380

test_stream_directory_xattr()
{
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
#
# Test against streams_xattr
#
    cat > $tmpfile <<EOF
deltree foo
mkdir foo
put ${PREFIX}/smbclient_interactive_prompt_commands foo:bar
setmode foo -a
allinfo foo:bar
deltree foo
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/streams_xattr -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed checking attributes on xattr stream foo:bar with error $ret"
	return 1
    fi

    echo "$out" | grep "attributes:.*80"
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed checking attributes on xattr stream foo:bar"
	return 1
    fi

#
# Test against streams_depot
#
    cat > $tmpfile <<EOF
deltree foo
mkdir foo
put ${PREFIX}/smbclient_interactive_prompt_commands foo:bar
setmode foo -a
allinfo foo:bar
deltree foo
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed checking attributes on depot stream foo:bar with error $ret"
	return 1
    fi

    echo "$out" | grep "attributes:.*80"
    ret=$?
    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed checking attributes on depot stream foo:bar"
	return 1
    fi
}

# Test smbclient non-empty rmdir command
test_del_nedir()
{
    tmpfile=$PREFIX/smbclient_interactive_prompt_commands
    del_nedir="$LOCAL_PATH/del_nedir"

    rm -rf $del_nedir
    mkdir $del_nedir
    touch $del_nedir/afile
    cat > $tmpfile <<EOF
rmdir del_nedir
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -rf $del_nedir

    if [ $ret != 0 ] ; then
	echo "$out"
	echo "failed test_del_nedir test with output $ret"
	false
	return
    fi

# Should get NT_STATUS_DIRECTORY_NOT_EMPTY error from rmdir
    echo "$out" | grep 'NT_STATUS_DIRECTORY_NOT_EMPTY'
    ret=$?
    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "test_del_nedir failed - should get an NT_STATUS_DIRECTORY_NOT_EMPTY error"
       false
       return
    fi
}

#
#
LOGDIR_PREFIX=test_smbclient_s3

# possibly remove old logdirs:

for OLDDIR in $(find ${PREFIX} -type d -name "${LOGDIR_PREFIX}_*") ;  do
	echo "removing old directory ${OLDDIR}"
	rm -rf ${OLDDIR}
done

LOGDIR=$(mktemp -d ${PREFIX}/${LOGDIR_PREFIX}_XXXXXX)


testit "smbclient -L $SERVER_IP" $SMBCLIENT -L $SERVER_IP -N -p 139 ${RAWARGS} || failed=`expr $failed + 1`
testit "smbclient -L $SERVER -I $SERVER_IP" $SMBCLIENT -L $SERVER -I $SERVER_IP -N -p 139 ${RAWARGS} -c quit || failed=`expr $failed + 1`

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

testit "list a share with a mangled name + acl_xattr object" \
    test_mangled_names || \
    failed=`expr $failed + 1`

testit "server-side file copy" \
    test_scopy || \
    failed=`expr $failed + 1`

testit "creating a :stream at root of share" \
    test_toplevel_stream || \
    failed=`expr $failed + 1`

testit "Ensure widelinks are restricted" \
    test_widelinks || \
    failed=`expr $failed + 1`

testit "streams_depot can delete correctly" \
    test_streams_depot_delete || \
    failed=`expr $failed + 1`

testit "stream_xattr attributes" \
    test_stream_directory_xattr || \
    failed=`expr $failed + 1`

testit "follow symlinks = no" \
    test_nosymlinks || \
    failed=`expr $failed + 1`

testit "follow local symlinks" \
    test_local_symlinks || \
    failed=`expr $failed + 1`

testit "noperm share regression" \
    test_noperm_share_regression || \
    failed=`expr $failed + 1`

testit "smbclient deltree command" \
    test_deltree || \
    failed=`expr $failed + 1`

testit "server os message" \
    test_server_os_message || \
    failed=`expr $failed + 1`

testit "test server quiet message" \
    test_server_quiet_message || \
    failed=`expr $failed + 1`

testit "setmode test" \
    test_setmode || \
    failed=`expr $failed + 1`

testit "utimes" \
    test_utimes || \
    failed=`expr $failed + 1`

testit "rename_dotdot" \
    test_rename_dotdot || \
    failed=`expr $failed + 1`

testit "volume" \
    test_volume || \
    failed=`expr $failed + 1`

testit "rm -rf $LOGDIR" \
    rm -rf $LOGDIR || \
    failed=`expr $failed + 1`

testit "delete a non empty directory" \
    test_del_nedir || \
    failed=`expr $failed + 1`

testok $0 $failed
