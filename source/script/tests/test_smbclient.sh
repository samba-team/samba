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

runcmd() {
	desc=$1
	cmd=$2
	shift 2
	echo $cmd
	bin/smbclient -c "$cmd" //$SERVER/tmp -U $DOMAIN\\$USERNAME%$PASSWORD
	return $?
}

incdir=`dirname $0`
. $incdir/test_functions.sh

# Generate random file
cat >tmpfile<<EOF
foo
bar
bloe
blah
EOF

# put that file
runcmd "Putting file" "mput tmpfile" || failed=`expr $failed + 1`
# check file info
runcmd "Getting alternative name" "altname tmpfile" || failed=`expr $failed + 1`
# run allinfo on that file
runcmd "Checking info on file" "allinfo tmpfile" || failed=`expr $failed + 1`
# get that file
mv tmpfile tmpfile-old
runcmd "Getting file" "mget tmpfile" || failed=`expr $failed + 1`
# remove that file
runcmd "Removing file" "rm tmpfile" || failed=`expr $failed + 1`
# compare locally
diff tmpfile-old tmpfile
# create directory
runcmd "Creating directory" "mkdir bla" || failed=`expr $failed + 1`
# cd to directory
runcmd "Changing directory" "cd bla" || failed=`expr $failed + 1`
# cd to top level directory
runcmd "Going back" "cd .." || failed=`expr $failed + 1`
# remove directory
runcmd "Removing directory" "rmdir bla" || failed=`expr $failed + 1`
# enable recurse, create nested directory
runcmd "Creating nested directory" "recurse; mkdir bla/bloe" || failed=`expr $failed + 1`
# remove parent directory
runcmd "Removing directory" "rmdir bla/bloe" || failed=`expr $failed + 1`
# remove child directory
runcmd "Removing directory" "rmdir bla" || failed=`expr $failed + 1`
# run fsinfo
runcmd "Getting file system info" "fsinfo objectid" || failed=`expr $failed + 1`

rm tmpfile tmpfile-old

testok $0 $failed
