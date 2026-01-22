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

# Test 1: Basic rate limiting
test_aio_ratelimit_basic()
{
	local testfile="${FUNCNAME[0]}"
	local src="${LOCAL_PATH}/${testfile}-src"
	local dst="${testfile}-dst"
	local tgt="${testfile}-tgt"

	# Small file to avoid timeout
	dd if=/dev/urandom of="${src}" bs=10K count=1
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

	# Read 20 times to trigger rate limiting
	count=1
	while [ $count -le 20 ]; do
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

	# Expect rate-limiting delay
	if [ ${SECONDS} -lt 1 ]; then
		printf "no rate-limiting delay observed: elapsed-secs=%d\n" "${SECONDS}"
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

# Test 2: Burst behavior - initial reads should be fast
test_aio_ratelimit_burst()
{
	local testfile="${FUNCNAME[0]}"
	local src="${LOCAL_PATH}/${testfile}-src"
	local dst="${testfile}-dst"
	local tgt="${testfile}-tgt"

	# Small file
	dd if=/dev/urandom of="${src}" bs=5K count=1
	stat "$src"

	# Write
	CLI_FORCE_INTERACTIVE=1 ${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} \
		-U${USER}%${PASSWORD} -c "put ${src} ${dst}"
	ret=$?
	if [ $ret != 0 ]; then
		printf "failed to write file: %s\n" "${ret}"
		return 1
	fi

	# First 3 reads should be fast (using burst)
	SECONDS=0
	count=1
	while [ $count -le 3 ]; do
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

	# Should complete quickly (burst capacity)
	if [ ${SECONDS} -gt 1 ]; then
		printf "burst reads too slow: elapsed-secs=%d\n" "${SECONDS}"
		return 1
	fi

	# Delete
	CLI_FORCE_INTERACTIVE=1 ${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} \
	    -U${USER}%${PASSWORD} -c "del ${dst}"

	# Cleanups
	rm -f "${src}" "${tgt}"
}

# Test 3: Recovery after idle
test_aio_ratelimit_recovery()
{
	local testfile="${FUNCNAME[0]}"
	local src="${LOCAL_PATH}/${testfile}-src"
	local dst="${testfile}-dst"
	local tgt="${testfile}-tgt"

	# Small file
	dd if=/dev/urandom of="${src}" bs=5K count=1
	stat "$src"

	# Write
	CLI_FORCE_INTERACTIVE=1 ${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} \
		-U${USER}%${PASSWORD} -c "put ${src} ${dst}"
	ret=$?
	if [ $ret != 0 ]; then
		printf "failed to write file: %s\n" "${ret}"
		return 1
	fi

	# Exhaust burst with 5 rapid reads
	count=1
	while [ $count -le 5 ]; do
		CLI_FORCE_INTERACTIVE=1 \
			${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} \
			-U${USER}%${PASSWORD} -c "get ${dst} ${tgt}" > /dev/null 2>&1
		(( count++ ))
	done

	# Wait for tokens to refill
	sleep 2

	# Read again - should be reasonably fast (tokens refilled)
	SECONDS=0
	CLI_FORCE_INTERACTIVE=1 \
		${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} \
		-U${USER}%${PASSWORD} -c "get ${dst} ${tgt}"
	ret=$?
	if [ $ret != 0 ]; then
		printf "failed to read after recovery: %s\n" "${ret}"
		return 1
	fi

	# Should complete quickly (tokens recovered)
	if [ ${SECONDS} -gt 1 ]; then
		printf "recovery too slow: elapsed-secs=%d\n" "${SECONDS}"
		return 1
	fi

	# Delete
	CLI_FORCE_INTERACTIVE=1 ${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} \
	    -U${USER}%${PASSWORD} -c "del ${dst}"

	# Cleanups
	rm -f "${src}" "${tgt}"
}

# Actual tests
testit "test_aio_ratelimit_basic" \
	test_aio_ratelimit_basic ||
	failed=$(expr $failed + 1)

testit "test_aio_ratelimit_burst" \
	test_aio_ratelimit_burst ||
	failed=$(expr $failed + 1)

testit "test_aio_ratelimit_recovery" \
	test_aio_ratelimit_recovery ||
	failed=$(expr $failed + 1)

testok $0 $failed
