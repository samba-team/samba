#!/bin/sh

# Basic script to make sure that cifsdd can do both local and remote I/O.

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_cifsdd.sh SERVER USERNAME PASSWORD DOMAIN
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
DOMAIN=$4

DD=bin/cifsdd

SHARE=tmp
DEBUGLEVEL=1

failed=0

failtest() {
	failed=`expr $failed + 1`
}

runcopy() {
	message="$1"
	shift
	
	testit "$message" $VALGRIND $DD $CONFIGURATION --debuglevel=$DEBUGLEVEL -W "$DOMAIN" -U "$USERNAME"%"$PASSWORD" \
	    "$@"
}

compare() {
    cmp "$1" "$2"
}

incdir=`dirname $0`
. $incdir/test_functions.sh

sourcepath=tempfile.src.$$
destpath=tempfile.dst.$$

# Create a source file with arbitrary contents
dd if=$DD of=$sourcepath bs=1024 count=50 > /dev/null

ls -l $sourcepath

for bs in 512 4k 48k ; do

echo "Testing $bs block size ..."

# Check whether we can do local IO
runcopy "Testing local -> local copy" if=$sourcepath of=$destpath bs=$bs || failtest
compare $sourcepath $destpath || failtest

# Check whether we can do a round trip
runcopy "Testing local -> remote copy" \
	    if=$sourcepath of=//$SERVER/$SHARE/$sourcepath bs=$bs || failtest
runcopy "Testing remote -> local copy" \
	    if=//$SERVER/$SHARE/$sourcepath of=$destpath bs=$bs || failtest
compare $sourcepath $destpath || failtest

# Check that copying within the remote server works
runcopy "Testing local -> remote copy" \
	    if=//$SERVER/$SHARE/$sourcepath of=//$SERVER/$SHARE/$sourcepath bs=$bs || failtest
runcopy "Testing remote -> remote copy" \
	    if=//$SERVER/$SHARE/$sourcepath of=//$SERVER/$SHARE/$destpath bs=$bs || failtest
runcopy "Testing remote -> local copy" \
	    if=//$SERVER/$SHARE/$destpath of=$destpath bs=$bs || failtest
compare $sourcepath $destpath || failtest

done

rm -f $sourcepath $destpath

testok $0 $failed
