#!/bin/sh

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
echo mkdir bla | runcmd "Creating directory" || failed=`expr $failed + 1`
# cd to directory
echo cd bla | runcmd "Changing directory" || failed=`expr $failed + 1`
# cd to top level directory
echo cd .. | runcmd "Going back" || failed=`expr $failed + 1`
# remove directory
echo rmdir bla | runcmd "Removing directory"  || failed=`expr $failed + 1`
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

rm -f tmpfile tmpfile-old tmpfilex

exit $failed
