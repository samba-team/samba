#!/usr/bin/env bash
#
# Test VFS module aio_ratelimit

SELF=$(basename "$0")
if [ $# -lt 5 ]; then
	echo Usage: "${SELF}" SERVERCONFFILE SMBCLIENT \
		SERVER LOCAL_PATH SHARENAME
	exit 1
fi

CONF="$1"
SMBCLIENT="$2"
SERVER="$3"
LOCAL_PATH="$4"
SHARE="$5"

# Do not let deprecated option warnings muck this up
SAMBA_DEPRECATED_SUPPRESS=1
export SAMBA_DEPRECATED_SUPPRESS

incdir="$(dirname "$0")/../../../testprogs/blackbox"
. $incdir/subunit.sh

failed=0

# Prepare
cd $SELFTEST_TMPDIR || exit 1

# Sub tests
test_aio_ratelimit()
{
	local testfile="${FUNCNAME[0]}"
	local src="${LOCAL_PATH}/${testfile}-src"
	local dst="${testfile}-dst"
	local tgt="${testfile}-tgt"

	# Create source file
	dd if=/dev/urandom of="${src}" bs=1M count=1
	stat "$src"

	SECONDS=0

	# Write
	CLI_FORCE_INTERACTIVE=1 ${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} \
		-U${USER}%${PASSWORD} -c "put ${src} ${dst}"
	ret=$?
	if [ $ret != 0 ]; then
		printf "failed to write file: %s\n" "${ret}"
		return 1
	fi

	# Read multiple times
	count=1
	while [ $count -le 10 ]; do
		CLI_FORCE_INTERACTIVE=1 \
			${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} \
			-U${USER}%${PASSWORD} -c "get ${dst} ${tgt}"
		ret=$?
		if [ $ret != 0 ]; then
			printf "failed to read file: %s\n" "${ret}"
			return 1
		fi
		(( count++ ))
	done

	# Expect a forced-delay
	if [ ${SECONDS} -lt 10 ]; then
		printf "no read delay: elapsed-secs=%d\n" "${SECONDS}"
		return 1
	fi

	# Delete
	CLI_FORCE_INTERACTIVE=1 ${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} \
	    -U${USER}%${PASSWORD} -c "del ${dst}"
	ret=$?
	if [ $ret != 0 ]; then
		printf "failed to delete file: %s\n" "${ret}"
		return 1
	fi

	# Cleanups
	rm -f "${src}" "${tgt}"
}

# Actual tests
testit "test_aio_ratelimit" \
	test_aio_ratelimit ||
	failed=$(expr $failed + 1)

testok $0 $failed
