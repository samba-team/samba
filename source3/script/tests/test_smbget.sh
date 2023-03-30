#!/bin/bash
#
# Blackbox test for smbget.
#

if [ $# -lt 8 ]; then
	cat <<EOF
Usage: test_smbget SERVER SERVER_IP DOMAIN REALM USERNAME PASSWORD WORKDIR SMBGET
EOF
	exit 1
fi

SERVER=${1}
SERVER_IP=${2}
DOMAIN=${3}
REALM=${4}
USERNAME=${5}
PASSWORD=${6}
WORKDIR=${7}
SMBGET="$VALGRIND ${8}"
shift 8

TMPDIR="$SELFTEST_TMPDIR"

incdir=$(dirname $0)/../../../testprogs/blackbox
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
	pushd $WORKDIR
	rm -rf dir1 dir2 testfile
	popd
}

clear_download_area()
{
	rm -rf dir1 dir2 testfile dir001 dir004
}

test_singlefile_guest()
{
	clear_download_area
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
	clear_download_area
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
	clear_download_area
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
	clear_download_area
	echo "user $USERNAME%$PASSWORD" >$TMPDIR/rcfile
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
	clear_download_area
	$SMBGET -v -R -U$USERNAME%$PASSWORD smb://$SERVER_IP/smbget/
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi

	cmp --silent $WORKDIR/testfile ./testfile &&
		cmp --silent $WORKDIR/dir1/testfile1 ./dir1/testfile1 &&
		cmp --silent $WORKDIR/dir2/testfile2 ./dir2/testfile2
	if [ $? -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi

	return 0
}

test_recursive_existing_dir()
{
	clear_download_area
	mkdir dir1
	$SMBGET -v -R -U$USERNAME%$PASSWORD smb://$SERVER_IP/smbget/
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi

	cmp --silent $WORKDIR/testfile ./testfile &&
		cmp --silent $WORKDIR/dir1/testfile1 ./dir1/testfile1 &&
		cmp --silent $WORKDIR/dir2/testfile2 ./dir2/testfile2
	if [ $? -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi

	return 0
}

test_recursive_with_empty()
{ # see Bug 13199
	clear_download_area
	# create some additional empty directories
	mkdir -p $WORKDIR/dir001/dir002/dir003
	mkdir -p $WORKDIR/dir004/dir005/dir006
	$SMBGET -v -R -U$USERNAME%$PASSWORD smb://$SERVER_IP/smbget/
	rc=$?
	rm -rf $WORKDIR/dir001
	rm -rf $WORKDIR/dir004
	if [ $rc -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi

	cmp --silent $WORKDIR/testfile ./testfile &&
		cmp --silent $WORKDIR/dir1/testfile1 ./dir1/testfile1 &&
		cmp --silent $WORKDIR/dir2/testfile2 ./dir2/testfile2
	if [ $? -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi

	if [ ! -d dir001/dir002/dir003 ] || [ ! -d dir004/dir005/dir006 ]; then
		echo 'ERROR: empty directories are not present'
		return 1
	fi

	return 0
}

test_resume()
{
	clear_download_area
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
	clear_download_area
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
	clear_download_area
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

	echo "modified" >>testfile
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

# Test accessing an msdfs path.
test_msdfs_link()
{
	${SMBGET} -v "-U${USERNAME}%${PASSWORD}" \
		"smb://${SERVER}/msdfs-share/deeppath/msdfs-src2/readable_file"
	ret=$?
	if [ ${ret} -ne 0 ]; then
		echo "ERROR: smbget failed with ${ret}"
		return 1
	fi

	return 0
}

# Tests --limit-rate. Getting the testfile (128K in size) with --limit-rate 100
# (that is 100KB/s) should take at least 1 sec to complete.
test_limit_rate()
{
	clear_download_area
	echo "$SMBGET -v -a --limit-rate 100 smb://$SERVER_IP/smbget/testfile"
	time_begin=$(date +%s)
	$SMBGET -v -a --limit-rate 100 smb://$SERVER_IP/smbget/testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi
	time_end=$(date +%s)
	cmp --silent $WORKDIR/testfile ./testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi
	if [ $((time_end - time_begin)) -lt 1 ]; then
		echo 'ERROR: It should take at least 1s to transfer 128KB with rate 100KB/s'
		return 1
	fi
	return 0
}


create_test_data

pushd $TMPDIR

failed=0
testit "download single file as guest" test_singlefile_guest ||
	failed=$(expr $failed + 1)

testit "download single file with -U" test_singlefile_U ||
	failed=$(expr $failed + 1)

testit "download single file with smb URL" test_singlefile_smburl ||
	failed=$(expr $failed + 1)

testit "download single file with rcfile" test_singlefile_rcfile ||
	failed=$(expr $failed + 1)

testit "recursive download" test_recursive_U ||
	failed=$(expr $failed + 1)

testit "recursive download (existing target dir)" test_recursive_existing_dir ||
	failed=$(expr $failed + 1)

testit "recursive download with empty directories" test_recursive_with_empty ||
	failed=$(expr $failed + 1)

testit "resume download" test_resume ||
	failed=$(expr $failed + 1)

testit "resume download (modified file)" test_resume_modified ||
	failed=$(expr $failed + 1)

testit "update" test_update ||
	failed=$(expr $failed + 1)

testit "msdfs" test_msdfs_link ||
	failed=$((failed + 1))

testit "limit rate" test_limit_rate ||
	failed=$((failed + 1))

clear_download_area

popd # TMPDIR

remove_test_data

exit $failed
