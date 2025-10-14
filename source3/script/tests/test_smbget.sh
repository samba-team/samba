#!/usr/bin/env bash
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
DOMAIN_USER=${7}
DOMAIN_USER_PASSWORD=${8}
WORKDIR=${9}
SMBGET="$VALGRIND ${10}"
shift 10

TMPDIR="$SELFTEST_TMPDIR"

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh
. "${incdir}/common_test_fns.inc"

samba_kinit=$(system_or_builddir_binary kinit "${BINDIR}" samba4kinit)
samba_texpect="${BINDIR}/texpect"

create_test_data()
{
	pushd $WORKDIR
	# Do not preload anything for dd
	LD_PRELOAD='' dd if=/dev/urandom bs=1024 count=128 of=testfile
	chmod 644 testfile
	mkdir dir1
	LD_PRELOAD='' dd if=/dev/urandom bs=1024 count=128 of=dir1/testfile1
	mkdir dir2
	LD_PRELOAD='' dd if=/dev/urandom bs=1024 count=128 of=dir2/testfile2
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
	rm -rf dir1 dir2 testfile dir001 dir004 readable_file
}

test_singlefile_guest()
{
	clear_download_area
	echo "$SMBGET --verbose --guest smb://$SERVER_IP/smbget_guest/testfile"
	$SMBGET --verbose --guest smb://$SERVER_IP/smbget_guest/testfile
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
	$SMBGET --verbose -U${SERVER}/${USERNAME}%$PASSWORD smb://$SERVER_IP/smbget/testfile
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

test_singlefile_U_UPN()
{
	clear_download_area

	${SMBGET} --verbose -U"${DOMAIN_USER}@${REALM}%${DOMAIN_USER_PASSWORD}" \
		"smb://${SERVER_IP}/smbget/testfile"
	ret=${?}
	if [ ${ret} -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi

	cmp --silent "${WORKDIR}/testfile" ./testfile
	ret=${?}
	if [ ${ret} -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi

	return 0
}

test_singlefile_U_domain()
{
	clear_download_area

	${SMBGET} --verbose -U"${DOMAIN}/${DOMAIN_USER}%${DOMAIN_USER_PASSWORD}" \
		"smb://${SERVER_IP}/smbget/testfile"
	ret=${?}
	if [ ${ret} -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi

	cmp --silent "${WORKDIR}/testfile" ./testfile
	ret=${?}
	if [ ${ret} -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi

	return 0
}

test_singlefile_smburl()
{
	clear_download_area
	$SMBGET --workgroup $DOMAIN smb://${DOMAIN_USER}:$DOMAIN_USER_PASSWORD@$SERVER_IP/smbget/testfile
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

test_singlefile_smburl2()
{
	clear_download_area
	$SMBGET "smb://$DOMAIN;${DOMAIN_USER}:$DOMAIN_USER_PASSWORD@$SERVER_IP/smbget/testfile"
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

test_singlefile_smburl_interactive()
{
	clear_download_area

	tmpfile="$(mktemp --tmpdir="${TMPDIR}" expect_XXXXXXXXXX)"

	cat >"${tmpfile}" <<EOF
expect Password for
send ${DOMAIN_USER_PASSWORD}\n
EOF

	USER="hanswurst" ${samba_texpect} "${tmpfile}" ${SMBGET} "smb://${DOMAIN};${DOMAIN_USER}@${SERVER_IP}/smbget/testfile"
	ret=$?
	rm -f "${tmpfile}"
	if [ ${ret} -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi
	cmp --silent $WORKDIR/testfile ./testfile
	ret=$?
	if [ ${ret} -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi
	return 0
}

test_singlefile_authfile()
{
	clear_download_area
	cat >"${TMPDIR}/authfile" << EOF
username = ${SERVER}/${USERNAME}
password = $PASSWORD
EOF
	$SMBGET --verbose --authentication-file="${TMPDIR}/authfile" smb://$SERVER_IP/smbget/testfile
	rc=$?
	rm -f $TMPDIR/authfile
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
	$SMBGET --verbose --recursive -U${SERVER}/${USERNAME}%$PASSWORD smb://$SERVER_IP/smbget/
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
	$SMBGET --verbose --recursive -U${SERVER}/${USERNAME}%$PASSWORD smb://$SERVER_IP/smbget/
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
	$SMBGET --verbose --recursive -U${SERVER}/${USERNAME}%$PASSWORD smb://$SERVER_IP/smbget/
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
	$SMBGET --verbose --resume -U${SERVER}/${USERNAME}%$PASSWORD smb://$SERVER_IP/smbget/testfile
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
	# Do not preload anything for dd
	LD_PRELOAD='' dd if=/dev/urandom bs=1024 count=2 of=testfile
	$SMBGET --verbose --resume -U${SERVER}/${USERNAME}%$PASSWORD smb://$SERVER_IP/smbget/testfile
	if [ $? -ne 1 ]; then
		echo 'ERROR: RC does not match, expected: 1'
		return 1
	fi

	return 0
}

test_update()
{
	clear_download_area
	$SMBGET --verbose -U${SERVER}/${USERNAME}%$PASSWORD smb://$SERVER_IP/smbget/testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi

	# secondary download should pass
	$SMBGET --verbose --update -U${SERVER}/${USERNAME}%$PASSWORD smb://$SERVER_IP/smbget/testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi

	echo "modified" >>testfile
	# touch source to trigger new download
	sleep 1
	touch -m $WORKDIR/testfile
	$SMBGET --verbose --update -U${SERVER}/${USERNAME}%$PASSWORD smb://$SERVER_IP/smbget/testfile
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
	clear_download_area

	${SMBGET} --verbose "-U${SERVER}/${USERNAME}%${PASSWORD}" \
		"smb://${SERVER}/msdfs-share/deeppath/msdfs-src2/readable_file"
	ret=$?
	if [ ${ret} -ne 0 ]; then
		echo "ERROR: smbget failed with ${ret}"
		return 1
	fi

	return 0
}

test_msdfs_link_domain()
{
	clear_download_area

	${SMBGET} --verbose "-U${DOMAIN}/${DOMAIN_USER}%${DOMAIN_USER_PASSWORD}" \
		"smb://${SERVER}/msdfs-share/deeppath/msdfs-src2/readable_file"
	ret=$?
	if [ ${ret} -ne 0 ]; then
		echo "ERROR: smbget failed with ${ret}"
		return 1
	fi

	return 0
}

test_msdfs_link_upn()
{
	clear_download_area

	${SMBGET} --verbose "-U${DOMAIN_USER}@${REALM}%${DOMAIN_USER_PASSWORD}" \
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
	echo "$SMBGET --verbose --guest --limit-rate 100 smb://$SERVER_IP/smbget_guest/testfile"
	time_begin=$(date +%s)
	$SMBGET --verbose --guest --limit-rate 100 smb://$SERVER_IP/smbget_guest/testfile
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

test_encrypt()
{
	clear_download_area
	$SMBGET --verbose --encrypt -U${SERVER}/${USERNAME}%$PASSWORD smb://$SERVER_IP/smbget/testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi
	cmp --silent $WORKDIR/testfile ./testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi

	clear_download_area
	$SMBGET --verbose --client-protection=encrypt -U${SERVER}/${USERNAME}%$PASSWORD smb://$SERVER_IP/smbget/testfile
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

test_kerberos()
{
	clear_download_area

	KRB5CCNAME_PATH="${TMPDIR}/smget_krb5ccache"
	rm -f "${KRB5CCNAME_PATH}"

	KRB5CCNAME="FILE:${KRB5CCNAME_PATH}"
	export KRB5CCNAME
	kerberos_kinit "${samba_kinit}" \
		"${DOMAIN_USER}@${REALM}" "${DOMAIN_USER_PASSWORD}"
	if [ $? -ne 0 ]; then
		echo 'Failed to get Kerberos ticket'
		return 1
	fi

	$SMBGET --verbose --use-krb5-ccache="${KRB5CCNAME}" \
		smb://$SERVER/smbget/testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: RC does not match, expected: 0'
		return 1
	fi

	cmp --silent $WORKDIR/testfile ./testfile
	if [ $? -ne 0 ]; then
		echo 'ERROR: file content does not match'
		return 1
	fi

	rm -f "${KRB5CCNAME_PATH}"

	return 0
}

test_kerberos_trust()
{
	clear_download_area

	$SMBGET --verbose --use-kerberos=required \
		-U"${TRUST_F_BOTH_USERNAME}@${TRUST_F_BOTH_REALM}%${TRUST_F_BOTH_PASSWORD}" \
		smb://$SERVER.${REALM}/smbget/testfile
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

# TODO FIXME
# This test does not work, as we can't tell the libsmb code that the
# principal is an enterprise principal. We need support for enterprise
# principals in kerberos_kinit_password_ext() and a way to pass it via the
# credenitals structure and commandline options.
# It works if you do: kinit -E testdenied_upn@${REALM}.upn
#
# test_kerberos_upn_denied()
# {
# 	set -x
# 	clear_download_area
#
# 	$SMBGET --verbose --use-kerberos=required \
# 		-U"testdenied_upn@${REALM}.upn%${DC_PASSWORD}" \
# 		"smb://${SERVER}.${REALM}/smbget/testfile" -d10
# 	if [ $? -ne 0 ]; then
# 		echo 'ERROR: RC does not match, expected: 0'
# 		return 1
# 	fi
#
# 	cmp --silent $WORKDIR/testfile ./testfile
# 	if [ $? -ne 0 ]; then
# 		echo 'ERROR: file content does not match'
# 		return 1
# 	fi
#
# 	return 0
# }

create_test_data

pushd $TMPDIR

failed=0
testit "download single file as guest" test_singlefile_guest ||
	failed=$(expr $failed + 1)

testit "download single file with -U" test_singlefile_U ||
	failed=$(expr $failed + 1)

testit "download single file with --update and domain" test_singlefile_U_domain ||
	failed=$((failed + 1))

testit "download single file with --update and UPN" test_singlefile_U_UPN ||
	failed=$((failed + 1))

testit "download single file with smb URL" test_singlefile_smburl ||
	failed=$(expr $failed + 1)

testit "download single file with smb URL including domain" \
	test_singlefile_smburl2 ||
	failed=$(expr $failed + 1)

testit "download single file with smb URL interactive" \
	test_singlefile_smburl_interactive ||
	failed=$(expr $failed + 1)

testit "download single file with authfile" test_singlefile_authfile ||
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

testit "msdfs.domain" test_msdfs_link_domain ||
	failed=$((failed + 1))

testit "msdfs.upn" test_msdfs_link_upn ||
	failed=$((failed + 1))

testit "limit rate" test_limit_rate ||
	failed=$((failed + 1))

testit "encrypt" test_encrypt ||
	failed=$((failed + 1))

testit "kerberos" test_kerberos ||
	failed=$((failed + 1))

testit "kerberos_trust" test_kerberos_trust ||
	failed=$((failed + 1))

# testit "kerberos_upn_denied" test_kerberos_upn_denied ||
# 	failed=$((failed + 1))

clear_download_area

popd # TMPDIR

remove_test_data

exit $failed
