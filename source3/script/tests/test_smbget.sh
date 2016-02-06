#!/bin/bash
#
# Blackbox test for smbget.
#

if [ $# -lt 7 ]; then
cat <<EOF
Usage: test_smbget SERVER SERVER_IP DOMAIN USERNAME PASSWORD WORKDIR SMBGET
EOF
exit 1;
fi

SERVER=${1}
SERVER_IP=${2}
DOMAIN=${3}
USERNAME=${4}
PASSWORD=${5}
WORKDIR=${6}
SMBGET="$VALGRIND ${7}"

TMPDIR="$SRCDIR_ABS/st/tmp"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

create_test_data()
{
	pushd $WORKDIR
	dd if=/dev/urandom bs=1024 count=128 of=testfile
	chmod 644 testfile
	mkdir dir1
	dd if=/dev/urandom bs=1024 count=128 of=dir1/testfile1
	mkdir dir2
	dd if=/dev/urandom bs=1024 count=128 of=dir2/testfile2
	popd
}

remove_test_data()
{
	rm -rf dir1 dir2 testfile
	pushd $WORKDIR
	rm -rf dir1 dir2 testfile
	popd
}

test_singlefile_guest()
{
	[ -e testfile ] && rm testfile
	echo "$SMBGET -v -a smb://$SERVER_IP/smbget/testfile"
	$SMBGET -v -a smb://$SERVER_IP/smbget/testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi
	cmp --silent $WORKDIR/testfile ./testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi
	return 0
}

test_singlefile_U()
{
	[ -e testfile ] && rm testfile
	$SMBGET -v -U$USERNAME%$PASSWORD smb://$SERVER_IP/smbget/testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi
	cmp --silent $WORKDIR/testfile ./testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi
	return 0
}

test_singlefile_smburl()
{
	[ -e testfile ] && rm testfile
	$SMBGET -w $DOMAIN smb://$USERNAME:$PASSWORD@$SERVER_IP/smbget/testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi
	cmp --silent $WORKDIR/testfile ./testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi
	return 0
}

test_singlefile_rcfile()
{
	[ -e testfile ] && rm testfile
	echo "user $USERNAME%$PASSWORD" > $TMPDIR/rcfile
	$SMBGET -vn -f $TMPDIR/rcfile smb://$SERVER_IP/smbget/testfile
	rc=$?
	rm -f $TMPDIR/rcfile
	if [ $rc -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi
	cmp --silent $WORKDIR/testfile ./testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi
	return 0
}

test_recursive_U()
{
	[ -e testfile ] && rm testfile
	[ -d dir1 ] && rm -rf dir1
	[ -d dir2 ] && rm -rf dir2
	$SMBGET -v -R -U$USERNAME%$PASSWORD smb://$SERVER_IP/smbget/
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi

	cmp --silent $WORKDIR/testfile ./testfile && \
	cmp --silent $WORKDIR/dir1/testfile1 ./dir1/testfile1 && \
	cmp --silent $WORKDIR/dir2/testfile2 ./dir2/testfile2
	if [ $? -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi

	return 0
}

test_resume()
{
	[ -e testfile ] && rm testfile
	cp $WORKDIR/testfile .
	truncate -s 1024 testfile
	$SMBGET -v -r -U$USERNAME%$PASSWORD smb://$SERVER_IP/smbget/testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi

	cmp --silent $WORKDIR/testfile ./testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi

	return 0
}

test_resume_modified()
{
	dd if=/dev/urandom bs=1024 count=2 of=testfile
	$SMBGET -v -r -U$USERNAME%$PASSWORD smb://$SERVER_IP/smbget/testfile
	if [ $? -ne 1 ]; then
		echo 'ERROR: RC does not match, expected: 1'
		return 1
	fi

	return 0
}

test_update()
{
	[ -e testfile ] && rm testfile
	$SMBGET -v -U$USERNAME%$PASSWORD smb://$SERVER_IP/smbget/testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi

	# secondary download should pass
	$SMBGET -v -u -U$USERNAME%$PASSWORD smb://$SERVER_IP/smbget/testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi

	echo "modified" >> testfile
	# touch source to trigger new download
	sleep 2
	touch -m $WORKDIR/testfile
	$SMBGET -v -u -U$USERNAME%$PASSWORD smb://$SERVER_IP/smbget/testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi

	cmp --silent $WORKDIR/testfile ./testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi

	return 0
}

create_test_data

pushd $TMPDIR

failed=0
testit "download single file as guest" test_singlefile_guest \
	|| failed=`expr $failed + 1`

testit "download single file with -U" test_singlefile_U \
	|| failed=`expr $failed + 1`

testit "download single file with smb URL" test_singlefile_smburl \
	|| failed=`expr $failed + 1`

testit "download single file with rcfile" test_singlefile_rcfile \
	|| failed=`expr $failed + 1`

testit "recursive download" test_recursive_U \
	|| failed=`expr $failed + 1`

testit "resume download" test_resume \
	|| failed=`expr $failed + 1`

testit "resume download (modified file)" test_resume_modified \
	|| failed=`expr $failed + 1`

testit "update" test_update \
	|| failed=`expr $failed + 1`

popd

remove_test_data

exit $failed
