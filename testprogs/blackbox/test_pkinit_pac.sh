#!/bin/sh
# Blackbox tests for pkinit and pac verification
#
# Copyright (C) 2006-2008 Stefan Metzmacher
# Copyright (C) 2022      Andreas Schneider

if [ $# -lt 6 ]; then
	cat <<EOF
Usage: test_pkinit_pac.sh SERVER USERNAME PASSWORD REALM DOMAIN PREFIX
EOF
	exit 1
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
REALM=$4
DOMAIN=$5
PREFIX=$6
shift 6
failed=0

samba_bindir="$BINDIR"

samba_smbtorture="${samba_bindir}/smbtorture --basedir=$SELFTEST_TMPDIR"

. "$(dirname "$0")"/subunit.sh
. "$(dirname "$0")"/common_test_fns.inc

samba_kinit=$(system_or_builddir_binary kinit "${BINDIR}" samba4kinit)

KRB5CCNAME_PATH="$PREFIX/tmpccache"
rm -f "${KRB5CCNAME_PATH}"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME

USER_PRINCIPAL_NAME="$(echo "${USERNAME}@${REALM}" | tr "[:upper:]" "[:lower:]")"

kbase="$(basename "${samba_kinit}")"
if [ "${kbase}" = "samba4kinit" ]; then
	# HEIMDAL
	X509_USER_IDENTITY="--pk-user=FILE:${PREFIX}/pkinit/USER-${USER_PRINCIPAL_NAME}-cert.pem,${PREFIX}/pkinit/USER-${USER_PRINCIPAL_NAME}-private-key.pem"
	OPTION_RENEWABLE="--renewable"
else
	X509_USER_IDENTITY="-X X509_user_identity=FILE:${PREFIX}/pkinit/USER-${USER_PRINCIPAL_NAME}-cert.pem,${PREFIX}/pkinit/USER-${USER_PRINCIPAL_NAME}-private-key.pem"
	OPTION_RENEWABLE="-r 1h"
fi
OPTION_REQUEST_PAC="--request-pac"

testit "STEP1 kinit with pkinit (name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${USERNAME}@${REALM}" ||
	failed=$((failed + 1))
testit "STEP1 remote.pac verification" \
	"${samba_smbtorture}" ncacn_np:"${SERVER}" rpc.pac \
	--workgroup="${DOMAIN}" -U"${USERNAME}%${PASSWORD}" \
	--option=torture:pkinit_ccache="${KRB5CCNAME}" ||
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"
exit ${failed}
