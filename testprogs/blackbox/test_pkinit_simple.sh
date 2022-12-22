#!/bin/sh
# Blackbox tests for kinit and kerberos integration with smbclient etc
#
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>
# Copyright (C) 2022      Andreas Schneider <asn@samba.org>

if [ $# -lt 7 ]; then
	cat <<EOF
Usage: test_pkinit_mit.sh SERVER USERNAME PASSWORD REALM DOMAIN PREFIX SMBCLINET
EOF
	exit 1
fi

SERVER="${1}"
USERNAME="${2}"
PASSWORD="${3}"
REALM="${4}"
DOMAIN="${5}"
PREFIX="${6}"
smbclient="${7}"
shift 7
failed=0

samba_bindir="${BINDIR}"

samba_tool="${PYTHON} ${samba_bindir}/samba-tool"
wbinfo="${samba_bindir}/wbinfo"

. "$(dirname "$0")"/subunit.sh
. "$(dirname "$0")"/common_test_fns.inc

samba_kinit=$(system_or_builddir_binary kinit "${BINDIR}" samba4kinit)

unc="//${SERVER}/tmp"

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
	OPTION_RENEW_TICKET="--renew"
	OPTION_ENTERPRISE_NAME="--enterprise"
else
	# MIT
	X509_USER_IDENTITY="-X X509_user_identity=FILE:${PREFIX}/pkinit/USER-${USER_PRINCIPAL_NAME}-cert.pem,${PREFIX}/pkinit/USER-${USER_PRINCIPAL_NAME}-private-key.pem"
	OPTION_RENEWABLE="-r 1h"
	OPTION_RENEW_TICKET="-R"
	OPTION_ENTERPRISE_NAME="-E"
fi
OPTION_REQUEST_PAC="--request-pac"

# STEP0:
# Now we set the UF_SMARTCARD_REQUIRED bit
# This means we have a normal enabled account *without* a known password
testit "STEP0 samba-tool user create ${USERNAME} --smartcard-required" \
	"${samba_tool}" user create "${USERNAME}" --smartcard-required ||
	failed=$((failed + 1))

testit_expect_failure "STEP1 kinit with password" \
	kerberos_kinit "${samba_kinit}" "${USERNAME}@${REALM}" "${PASSWORD}" \
	"${OPTION_REQUEST_PAC}" ||
	failed=$((failed + 1))
testit_expect_failure "STEP1 Test login with NTLM" \
	"${smbclient}" "${unc}" -c 'ls' "-U${USERNAME}%${PASSWORD}" ||
	failed=$((failed + 1))
testit_expect_failure "STEP1 Test wbinfo with password" \
	"${wbinfo}" "--authenticate=$DOMAIN/$USERNAME%$PASSWORD" ||
	failed=$((failed + 1))

testit "STEP1 kinit with pkinit (name specified: ${USERNAME})" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${USERNAME}@${REALM}" ||
	failed=$((failed + 1))

testit "STEP1 kinit renew ticket (name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEW_TICKET}" ||
	failed=$((failed + 1))
test_smbclient "STEP1 Test login with kerberos ccache (name specified)" \
	'ls' "$unc" --use-krb5-ccache="${KRB5CCNAME}" ||
	failed=$((failed + 1))

# OK
testit_expect_failure "STEP1 kinit with pkinit (wrong name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "not${USERNAME}@${REALM}" ||
	failed=$((failed + 1))

testit_expect_failure "STEP1 kinit with pkinit (wrong name specified 2)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${SERVER}@${REALM}" ||
	failed=$((failed + 1))

testit "STEP1 kinit with pkinit (enterprise name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${OPTION_ENTERPRISE_NAME}" \
	"${USERNAME}@${REALM}" ||
	failed=$((failed + 1))
testit "STEP1 kinit renew ticket (enterprise name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEW_TICKET}" ||
	failed=$((failed + 1))
test_smbclient "STEP1 Test login with kerberos ccache (enterprise name specified)" \
	'ls' "${unc}" --use-krb5-ccache="${KRB5CCNAME}" ||
	failed=$((failed + 1))
testit_expect_failure "STEP1 kinit with pkinit (wrong enterprise name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${OPTION_ENTERPRISE_NAME}" \
	"not${USERNAME}@${REALM}" ||
	failed=$((failed + 1))
testit_expect_failure "STEP1 kinit with pkinit (wrong enterprise name specified 2)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${OPTION_ENTERPRISE_NAME}" \
	"${SERVER}@${REALM}" ||
	failed=$((failed + 1))

testit "STEP1 kinit with pkinit (enterprise name in cert)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${OPTION_ENTERPRISE_NAME}" ||
	failed=$((failed + 1))
testit "STEP1 kinit renew ticket (enterprise name in cert)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEW_TICKET}" ||
	failed=$((failed + 1))
test_smbclient "STEP1 Test login with kerberos ccache (enterprise name in cert)" \
	'ls' "${unc}" --use-krb5-ccache="${KRB5CCNAME}" ||
	failed=$((failed + 1))

# STEP2:
# We still have UF_SMARTCARD_REQUIRED, but with a known password
testit "STEP2 samba-tool user setpassword ${USERNAME} --newpassword" \
	"${samba_tool}" user setpassword "${USERNAME}" \
	--newpassword="${PASSWORD}" ||
	failed=$((failed + 1))

testit_expect_failure "STEP2 kinit with password" \
	kerberos_kinit "${samba_kinit}" "${USERNAME}@${REALM}" "${PASSWORD}" \
	"${OPTION_REQUEST_PAC}" ||
	failed=$((failed + 1))
test_smbclient "STEP2 Test login with NTLM" \
	'ls' "$unc" -U"${USERNAME}%${PASSWORD}" ||
	failed=$((failed + 1))
testit_expect_failure "STEP2 Test wbinfo with password" \
	"${wbinfo}" --authenticate="${DOMAIN}/${USERNAME}%${PASSWORD}" ||
	failed=$((failed + 1))

testit "STEP2 kinit with pkinit (name specified) " \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${USERNAME}@${REALM}" ||
	failed=$((failed + 1))
testit "STEP2 kinit renew ticket (name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEW_TICKET}" ||
	failed=$((failed + 1))
test_smbclient "STEP2 Test login with kerberos ccache (name specified)" \
	'ls' "$unc" --use-krb5-ccache="${KRB5CCNAME}" ||
	failed=$((failed + 1))

testit "STEP2 kinit with pkinit (enterprise name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${OPTION_ENTERPRISE_NAME}" \
	"${USERNAME}@${REALM}" ||
	failed=$((failed + 1))
testit "STEP2 kinit renew ticket (enterprise name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEW_TICKET}" ||
	failed=$((failed + 1))
test_smbclient "STEP2 Test login with kerberos ccache (enterprise name specified)" \
	'ls' "$unc" --use-krb5-ccache="${KRB5CCNAME}" ||
	failed=$((failed + 1))

testit "STEP2 kinit with pkinit (enterprise name in cert)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${OPTION_ENTERPRISE_NAME}" ||
	failed=$((failed + 1))
testit "STEP2 kinit renew ticket (enterprise name in cert)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEW_TICKET}" ||
	failed=$((failed + 1))
test_smbclient "STEP2 Test login with kerberos ccache (enterprise name in cert)" \
	'ls' "$unc" --use-krb5-ccache="${KRB5CCNAME}" ||
	failed=$((failed + 1))

# STEP3:
# The account is a normal account without the UF_SMARTCARD_REQUIRED bit set
testit "STEP3 samba-tool user setpassword ${USERNAME} --clear-smartcard-required" \
	"${samba_tool}" user setpassword "${USERNAME}" \
	--newpassword="${PASSWORD}" --clear-smartcard-required ||
	failed=$((failed + 1))

testit "STEP3 kinit with password" \
	kerberos_kinit "${samba_kinit}" "${USERNAME}@${REALM}" "${PASSWORD}" \
	"${OPTION_REQUEST_PAC}" ||
	failed=$((failed + 1))
test_smbclient "STEP3 Test login with user kerberos ccache" \
	'ls' "$unc" --use-krb5-ccache="${KRB5CCNAME}" ||
	failed=$((failed + 1))
test_smbclient "STEP3 Test login with NTLM" \
	'ls' "$unc" -U"${USERNAME}%${PASSWORD}" ||
	failed=$((failed + 1))
testit "STEP3 Test wbinfo with password" \
	"${wbinfo}" --authenticate="${DOMAIN}/${USERNAME}%${PASSWORD}" ||
	failed=$((failed + 1))

testit "STEP3 kinit with pkinit (name specified) " \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${USERNAME}@${REALM}" ||
	failed=$((failed + 1))
testit "STEP3 kinit renew ticket (name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEW_TICKET}" ||
	failed=$((failed + 1))
test_smbclient "STEP3 Test login with kerberos ccache (name specified)" \
	'ls' "${unc}" --use-krb5-ccache="${KRB5CCNAME}" ||
	failed=$((failed + 1))

testit "STEP3 kinit with pkinit (enterprise name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${OPTION_ENTERPRISE_NAME}" \
	"${USERNAME}@${REALM}" ||
	failed=$((failed + 1))
testit "STEP3 kinit renew ticket (enterprise name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEW_TICKET}" ||
	failed=$((failed + 1))
test_smbclient "STEP3 Test login with kerberos ccache (enterprise name specified)" \
	'ls' "${unc}" --use-krb5-ccache="${KRB5CCNAME}" ||
	failed=$((failed + 1))

testit "STEP3 kinit with pkinit (enterprise name in cert)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${OPTION_ENTERPRISE_NAME}" ||
	failed=$((failed + 1))
testit "STEP3 kinit renew ticket (enterprise name in cert)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEW_TICKET}" ||
	failed=$((failed + 1))
test_smbclient "STEP3 Test login with kerberos ccache (enterprise name in cert)" \
	'ls' "${unc}" --use-krb5-ccache="${KRB5CCNAME}" ||
	failed=$((failed + 1))

# STEP4:
# Now we set the UF_SMARTCARD_REQUIRED bit
# This means we have a normal enabled account *without* a known password
testit "STEP4 samba-tool user setpassword $USERNAME --smartcard-required" \
	"${samba_tool}" user setpassword "${USERNAME}" --smartcard-required ||
	failed=$((failed + 1))

testit_expect_failure "STEP4 kinit with password" \
	kerberos_kinit "${samba_kinit}" "${USERNAME}@${REALM}" "${PASSWORD}" \
	"${OPTION_REQUEST_PAC}" ||
	failed=$((failed + 1))
testit_expect_failure "STEP4 Test login with NTLM" \
	"${smbclient}" "${unc}" -c 'ls' -U"${USERNAME}%${PASSWORD}" ||
	failed=$((failed + 1))
testit_expect_failure "STEP4 Test wbinfo with password" \
	"${wbinfo}" --authenticate="${DOMAIN}/${USERNAME}%${PASSWORD}" ||
	failed=$((failed + 1))

testit "STEP4 kinit with pkinit (name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${USERNAME}@${REALM}" ||
	failed=$((failed + 1))
testit "STEP4 kinit renew ticket (name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEW_TICKET}" ||
	failed=$((failed + 1))
test_smbclient "STEP4 Test login with kerberos ccache (name specified)" \
	'ls' "$unc" --use-krb5-ccache="${KRB5CCNAME}" ||
	failed=$((failed + 1))

testit "STEP4 kinit with pkinit (enterprise name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${OPTION_ENTERPRISE_NAME}" \
	"${USERNAME}@${REALM}" ||
	failed=$((failed + 1))
testit "STEP4 kinit renew ticket (enterprise name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEW_TICKET}" ||
	failed=$((failed + 1))
test_smbclient "STEP4 Test login with kerberos ccache (enterprise name specified)" \
	'ls' "${unc}" --use-krb5-ccache="${KRB5CCNAME}" ||
	failed=$((failed + 1))

testit "STEP4 kinit with pkinit (enterprise name in cert)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${OPTION_ENTERPRISE_NAME}" ||
	failed=$((failed + 1))
testit "STEP4 kinit renew ticket (enterprise name in cert)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEW_TICKET}" ||
	failed=$((failed + 1))
test_smbclient "STEP4 Test login with kerberos ccache (enterprise name in cert)" \
	'ls' "${unc}" --use-krb5-ccache="${KRB5CCNAME}" ||
	failed=$((failed + 1))

# STEP5:
# disable the account
testit "STEP5 samba-tool user disable $USERNAME" \
	"${samba_tool}" user disable "${USERNAME}" ||
	failed=$((failed + 1))

testit_expect_failure "STEP5 kinit with password" \
	kerberos_kinit "${samba_kinit}" "${USERNAME}@${REALM}" "${PASSWORD}" \
	"${OPTION_REQUEST_PAC}" ||
	failed=$((failed + 1))
testit_expect_failure "STEP5 Test login with NTLM" \
	"${smbclient}" "${unc}" -c 'ls' -U"${USERNAME}%${PASSWORD}" ||
	failed=$((failed + 1))
testit_expect_failure "STEP5 Test wbinfo with password" \
	"${wbinfo}" --authenticate="${DOMAIN}/${USERNAME}%${PASSWORD}" ||
	failed=$((failed + 1))

testit_expect_failure "STEP5 kinit with pkinit (name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${USERNAME}@${REALM}" ||
	failed=$((failed + 1))
testit_expect_failure "STEP5 kinit with pkinit (enterprise name specified)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${OPTION_ENTERPRISE_NAME}" \
	"${USERNAME}@${REALM}" ||
	failed=$((failed + 1))
testit_expect_failure "STEP5 kinit with pkinit (enterprise name in cert)" \
	"${samba_kinit}" "${OPTION_REQUEST_PAC}" "${OPTION_RENEWABLE}" \
	"${X509_USER_IDENTITY}" "${OPTION_ENTERPRISE_NAME}" ||
	failed=$((failed + 1))

# STEP6:
# cleanup
testit "STEP6 samba-tool user delete ${USERNAME}" \
	"${samba_tool}" user delete "${USERNAME}" ||
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"
exit ${failed}
