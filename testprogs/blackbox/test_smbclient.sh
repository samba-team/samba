#!/bin/sh
# Blackbox tests for smbclient
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2007 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_smbclient.sh SERVER USERNAME PASSWORD DOMAIN PREFIX
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
DOMAIN=$4
PREFIX=$5
shift 5
failed=0

testit() {
	name="$1"
	shift
	cmdline="$*"
	echo "test: $name"
	$cmdline
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
	fi
	return $status
}

runcmd() {
	name="$1"
	shift
	testit "$name" $VALGRIND bin/smbclient $CONFIGURATION //$SERVER/tmp -W "$DOMAIN" -U"$USERNAME%$PASSWORD" $@
	return $?
}

testit "share and server list" $VALGRIND bin/smbclient -L $SERVER $CONFIGURATION  -W "$DOMAIN" -U"$USERNAME%$PASSWORD" $@ || failed=`expr $failed + 1`

testit "domain join" $VALGRIND bin/net join $DOMAIN $CONFIGURATION  -W "$DOMAIN" -U"$USERNAME%$PASSWORD" $@ || failed=`expr $failed + 1`

# Generate random file
cat >tmpfile<<EOF
foo
bar
bloe
blah
EOF

# put that file
echo mput tmpfile | runcmd "MPutting file" || failed=`expr $failed + 1`
# check file info
echo altname tmpfile | runcmd "Getting alternative name" || failed=`expr $failed + 1`
# run allinfo on that file
echo allinfo tmpfile | runcmd "Checking info on file" || failed=`expr $failed + 1`
# get that file
mv tmpfile tmpfile-old
echo mget tmpfile | runcmd "MGetting file" || failed=`expr $failed + 1`
# remove that file
echo rm tmpfile | runcmd "Removing file" || failed=`expr $failed + 1`
# compare locally
testit "Comparing files" diff tmpfile-old tmpfile || failed=`expr $failed + 1`
# create directory
# cd to directory
# cd to top level directory
# remove directory
echo "mkdir bla; cd bla; cd ..; rmdir bla" | runcmd "Creating directory, Changing directory, Going back, " || failed=`expr $failed + 1`
# enable recurse, create nested directory
echo "recurse; echo mkdir bla/bloe; exit" | runcmd "Creating nested directory" || failed=`expr $failed + 1`
# remove parent directory
echo rmdir bla/bloe | runcmd "Removing directory" || failed=`expr $failed + 1`
# remove child directory
echo rmdir bla | runcmd "Removing directory" || failed=`expr $failed + 1`
# run fsinfo
echo fsinfo objectid | runcmd "Getting file system info" || failed=`expr $failed + 1`

# put that file
echo put tmpfile | runcmd "Putting file" || failed=`expr $failed + 1`
# get that file
mv tmpfile tmpfile-old
echo get tmpfile | runcmd "Getting file" || failed=`expr $failed + 1`
# remove that file
echo rm tmpfile | runcmd "Removing file" || failed=`expr $failed + 1`
# compare locally
testit "Comparing files" diff tmpfile-old tmpfile || failed=`expr $failed + 1`
# put that file
echo put tmpfile tmpfilex | runcmd "Putting file with different name" || failed=`expr $failed + 1`
# get that file
echo get tmpfilex | runcmd "Getting file again" || failed=`expr $failed + 1`
# compare locally
testit "Comparing files" diff tmpfilex tmpfile || failed=`expr $failed + 1`
# remove that file
echo rm tmpfilex | runcmd "Removing file" || failed=`expr $failed + 1`

# do some simple operations using old protocol versions
echo ls | runcmd "List directory with LANMAN1" -m LANMAN1 || failed=`expr $failed + 1`
echo ls | runcmd "List directory with LANMAN2" -m LANMAN2 || failed=`expr $failed + 1`

echo pwd | runcmd "Print current working directory" || failed=`expr $failed + 1`

echo ls | testit "Test login with --machine-pass without kerberos" $VALGRIND bin/smbclient $CONFIGURATION //$SERVER/tmp --machine-pass -k no || failed=`expr $failed + 1`

echo ls | testit "Test login with --machine-pass and kerberos" $VALGRIND bin/smbclient $CONFIGURATION //$SERVER/tmp --machine-pass -k yes || failed=`expr $failed + 1`

(
    echo "password=$PASSWORD"
    echo "username=$USERNAME"
    echo "domain=$DOMAIN"
) > tmpauthfile

echo ls | testit "Test login with --authentication-file" $VALGRIND bin/smbclient $CONFIGURATION //$SERVER/tmp --authentication-file=tmpauthfile  || failed=`expr $failed + 1`

PASSWD_FILE="tmppassfile" 
echo "$PASSWORD" > $PASSWD_FILE
export PASSWD_FILE
echo ls | testit "Test login with PASSWD_FILE" $VALGRIND bin/smbclient $CONFIGURATION //$SERVER/tmp -W "$DOMAIN" -U"$USERNAME" || failed=`expr $failed + 1`
PASSWD_FILE=""
export PASSWD_FILE
unset PASSWD_FILE

PASSWD="$PASSWORD" 
export PASSWD
echo ls | testit "Test login with PASSWD" $VALGRIND bin/smbclient $CONFIGURATION //$SERVER/tmp -W "$DOMAIN" -U"$USERNAME" || failed=`expr $failed + 1`

oldUSER=$USER
USER="$USERNAME" 
export USER
echo ls | testit "Test login with USER and PASSWD" $VALGRIND bin/smbclient $CONFIGURATION //$SERVER/tmp -W "$DOMAIN" | failed=`expr $failed + 1`
PASSWD=
export PASSWD
unset PASSWD
USER=$oldUSER
export USER

rm -f tmpfile tmpfile-old tmpfilex tmpauthfile tmppassfile
exit $failed
