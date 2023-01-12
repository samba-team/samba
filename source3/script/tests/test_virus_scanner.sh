#!/bin/sh
# Copyright (c) 2022      Pavel Filipenský <pfilipen@redhat.com>
# shellcheck disable=1091

if [ $# -lt 4 ]; then
	cat <<EOF
Usage: $0 SERVER_IP SHARE LOCAL_PATH SMBCLIENT
EOF
	exit 1
fi

SERVER_IP=${1}
SHARE=${2}
LOCAL_PATH=${3}
SMBCLIENT=${4}

SMBCLIENT="${VALGRIND} ${SMBCLIENT}"

failed=0
sharedir="${LOCAL_PATH}/${SHARE}"

incdir="$(dirname "$0")/../../../testprogs/blackbox"
. "${incdir}/subunit.sh"

check_infected_read()
{
	rm -rf "${sharedir:?}"/*

	if ! mkdir "${sharedir}/read1"; then
		echo "ERROR: Cannot create ${sharedir}/read1"
		return 1
	fi

	if ! mkdir "${sharedir}/read1/read2"; then
		echo "ERROR: Cannot create ${sharedir}/read1/read2"
		return 1
	fi

	if ! touch "${sharedir}/read1/read2/infected.txt"; then
		echo "ERROR: Cannot create ${sharedir}/read1/read2/infected.txt"
		return 1
	fi

	${SMBCLIENT} "//${SERVER_IP}/${SHARE}" -U"${USER}"%"${PASSWORD}" -c "get read1/read2/infected.txt ${sharedir}/read1/read2/infected.download.txt"

	# check that virusfilter:rename prefix/suffix was added
	if [ ! -f "${sharedir}/read1/read2/virusfilter.infected.txt.infected" ]; then
		echo "ERROR: ${sharedir}/read1/read2/virusfilter.infected.txt.infected is missing."
		return 1
	fi

	# check that file was not downloaded
	if [ -f "${sharedir}/read1/read2/infected.download.txt" ]; then
		echo "ERROR: {sharedir}/read1/read2/infected.download.txt should not exist."
		return 1
	fi

	rm -rf "${sharedir:?}"/*
	return 0
}

check_infected_write()
{
	rm -rf "${sharedir:?}"/*
	smbfile=infected.upload.txt
	smbfilerenamed="virusfilter.${smbfile}.infected"

	# non empty file is needed
	# vsf_virusfilter performs a scan only if fsp->fsp_flags.modified
	if ! echo "Hello Virus!" >"${sharedir}/infected.txt"; then
		echo "ERROR: Cannot create ${sharedir}/infected.txt"
		return 1
	fi

	${SMBCLIENT} "//${SERVER_IP}/${SHARE}" -U"${USER}"%"${PASSWORD}" -c "put ${sharedir}/infected.txt ${smbfile}"

	# check that virusfilter:rename prefix/suffix was added
	if [ ! -f "${sharedir}/${smbfilerenamed}" ]; then
		echo "ERROR: ${sharedir}/${smbfilerenamed} is missing."
		return 1
	fi

	# check that file was not uploaded
	if [ -f "${sharedir}/infected.upload.txt" ]; then
		echo "ERROR: {sharedir}/${smbfile} should not exist."
		return 1
	fi

	return 0
}

check_healthy_read()
{
	rm -rf "${sharedir:?}"/*

	if ! echo "Hello Samba!" >"${sharedir}/healthy.txt"; then
		echo "ERROR: Cannot create ${sharedir}/healthy.txt"
		return 1
	fi

	${SMBCLIENT} //"${SERVER_IP}"/"${SHARE}" -U"${USER}"%"${PASSWORD}" -c "get healthy.txt ${sharedir}/healthy.download.txt"

	if ! cmp "${sharedir}/healthy.txt" "${sharedir}/healthy.download.txt"; then
		echo "ERROR: cmp ${sharedir}/healthy.txt ${sharedir}/healthy.download.txt FAILED"
		return 1
	fi

	return 0
}

check_healthy_write()
{
	rm -rf "${sharedir:?}"/*

	if ! echo "Hello Samba!" >"${sharedir}/healthy.txt"; then
		echo "ERROR: Cannot create ${sharedir}/healthy.txt"
		return 1
	fi

	${SMBCLIENT} //"${SERVER_IP}"/"${SHARE}" -U"${USER}"%"${PASSWORD}" -c "put ${sharedir}/healthy.txt healthy.upload.txt"

	if ! cmp "${sharedir}/healthy.txt" "${sharedir}/healthy.upload.txt"; then
		echo "ERROR: cmp ${sharedir}/healthy.txt ${sharedir}/healthy.upload.txt FAILED"
		return 1
	fi

	return 0
}

testit "check_infected_read" check_infected_read || failed=$((failed + 1))
testit "check_infected_write" check_infected_write || failed=$((failed + 1))
testit "check_healthy_read" check_healthy_read || failed=$((failed + 1))
testit "check_healthy_write" check_healthy_write || failed=$((failed + 1))

testok "$0" "$failed"
