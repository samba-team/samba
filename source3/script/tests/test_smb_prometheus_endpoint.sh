#!/bin/sh

# This runs smbstatus tests

if [ $# -lt 10 ]; then
	echo "Usage: $0 SERVER SERVER_IP USERNAME PASSWORD LOCK_DIR PREFIX SMBPROMETHEUS SMBCLIENT CONFIGURATION PROTOCOL"
	exit 1
fi

SERVER="${1}"
SERVER_IP="${2}"
USERNAME="${3}"
PASSWORD="${4}"
LOCK_DIR="${5}"
PREFIX="${6}"
SMBPROMETHEUS="${7}"
SMBCLIENT="${8}"
CONFIGURATION="${9}"
PROTOCOL="${10}"

shift 10

RAWARGS="${CONFIGURATION} -m${PROTOCOL}"
ADDARGS="${RAWARGS} $*"
SMBPROFILE_TDB="${LOCK_DIR}/smbprofile.tdb"
SMBPROMETHEUS_PORT=9922
SMBPROMETHEUS_PID=0

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

start_smbprometheus()
{
	if [ ! -f "${SMBPROFILE_TDB}" ]; then
		printf "'%s' doesn't exist\n" "${SMBPROFILE_TDB}"
		return 1
	fi

	if [ ! -x "${SMBPROMETHEUS}" ]; then
		printf "'%s' is not executable\n" "${SMBPROMETHEUS}"
		return 1
	fi

	${SMBPROMETHEUS} -a "${SERVER_IP}" -p "${SMBPROMETHEUS_PORT}" "${SMBPROFILE_TDB}" &
	SMBPROMETHEUS_PID=$!
	sleep 1

	cmd='ps -p ${SMBPROMETHEUS_PID} --no-headers'
	eval "$cmd"
	ret=$?
	if [ $ret != 0 ]; then
		printf "failed to start: '%s' is not running\n" "${SMBPROMETHEUS}"
		return 1
	fi

	sleep 1

	return 0
}

stop_smbprometheus()
{
	cmd='ps -p ${SMBPROMETHEUS_PID} --no-headers'
	eval "$cmd"
	ret=$?
	if [ $ret != 0 ]; then
		printf "failed to stop: '%s' is not running\n" "${SMBPROMETHEUS}"
		return 1
	fi
	kill $SMBPROMETHEUS_PID
	return 0
}

make_some_smb_ops()
{
	tmpfile=$PREFIX/test_smb_prometheus

	cat >$tmpfile <<EOF
du
dir
quit
EOF

	cmd='CLI_FORCE_INTERACTIVE=yes ${SMBCLIENT} -U${USERNAME}%${PASSWORD} //${SERVER}/tmp -I ${SERVER_IP} ${ADDARGS} < $tmpfile 2>&1'
	out=$(eval "$cmd")
	ret=$?
	rm -f "$tmpfile"

	if [ $ret != 0 ]; then
		printf "failed to issue smb commands: %s\n" "${ret}"
		return 1
	fi

	return 0
}


# Read metrics with cURL, expect at least one tcon
test_smbprometheus_tcon()
{
	if ! make_some_smb_ops; then return 1; fi

	cmd='curl -s --connect-timeout 10 http://${SERVER_IP}:${SMBPROMETHEUS_PORT}/metrics'
	out=$(eval "$cmd")
	ret=$?
	if [ $ret != 0 ]; then
		printf "failed to read metrics %s\n" "$ret"
		return 1
	fi

	cmd="echo $out | grep tcon | wc -l"
	out=$(eval "$cmd")
	if [ "$out" = "0" ]; then
		printf "failed to read tcon metrics %s\n" "$ret"
		return 1
	fi

	return 0
}

# Expect specific metrics info
test_smbprometheus_info()
{
	if ! make_some_smb_ops; then return 1; fi

	cmd='curl -s --connect-timeout 10 http://${SERVER_IP}:${SMBPROMETHEUS_PORT}/metrics'
	out=$(eval "$cmd")
	ret=$?
	if [ $ret != 0 ]; then
		printf "failed to read metrics %s\n" "$ret"
		return 1
	fi

	subs="smb_worker_smbd_num smb_smb2_request_inbytes smb_smb2_request_outbytes smb_smb2_request_duration_microseconds_bucket"
	for sub in ${subs}; do
		cnt=$(echo "${out}" | grep -c "${sub}")
		if [ "$cnt" = "0" ]; then
			printf "failed to read metrics %s\n" "$sub"
			return 1
		fi
	done
}

# Read metrics multiple times
test_smbprometheus_many()
{
	if ! make_some_smb_ops; then return 1; fi

	cmd='curl -s --connect-timeout 10 http://${SERVER_IP}:${SMBPROMETHEUS_PORT}/metrics'
	for i in $(seq 0 100); do
		out=$(eval "$cmd")
		ret=$?
		if [ $ret != 0 ]; then
			printf "failed to read metrics %s\n" "$ret"
			return 1
		fi
		cnt=$(echo "${out}" | grep -c "smb_worker_smbd_num")
		if [ "$cnt" = "0" ]; then
			printf "failed to read metrics %s\n" "$out"
			return 1
		fi
	done

	return 0
}

# Require curl utility
if ! command -v curl > /dev/null; then exit 0; fi

# Start smb_prometheus_endpoint from within test script
start_smbprometheus || exit 1
trap "stop_smbprometheus" EXIT

# Actual tests
testit "test_smbprometheus_tcon" \
	test_smbprometheus_tcon ||
	failed=$(expr $failed + 1)

testit "test_smbprometheus_info" \
	test_smbprometheus_info ||
	failed=$(expr $failed + 1)

testit "test_smbprometheus_many" \
	test_smbprometheus_many ||
	failed=$(expr $failed + 1)

testok $0 $failed
