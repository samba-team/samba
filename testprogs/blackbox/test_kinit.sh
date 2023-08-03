#!/bin/sh
# Blackbox tests for kinit and kerberos integration with smbclient etc
# Copyright (c) Andreas Schneider <asn@samba.org>
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 8 ]; then
	cat <<EOF
Usage: test_kinit.sh SERVER USERNAME PASSWORD REALM DOMAIN PREFIX SMBCLIENT CONFIGURATION
EOF
	exit 1
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
REALM=$4
DOMAIN=$5
PREFIX=$6
smbclient=$7
CONFIGURATION="${8}"
shift 8
failed=0

. "$(dirname "${0}")/subunit.sh"
. "$(dirname "${0}")/common_test_fns.inc"

samba_bindir="$BINDIR"
samba_srcdir="$SRCDIR/source4"
samba_kinit=$(system_or_builddir_binary kinit "${BINDIR}" samba4kinit)
samba_kpasswd=$(system_or_builddir_binary kpasswd "${BINDIR}" samba4kpasswd)
samba_kvno=$(system_or_builddir_binary kvno "${BINDIR}" samba4kvno)

samba_tool="${samba_bindir}/samba-tool"
samba_texpect="${samba_bindir}/texpect"

samba_enableaccount="${samba_tool} user enable"
machineaccountccache="${samba_srcdir}/scripting/bin/machineaccountccache"

ldbmodify=$(system_or_builddir_binary ldbmodify "${BINDIR}")
ldbsearch=$(system_or_builddir_binary ldbsearch "${BINDIR}")

kbase="$(basename "${samba_kinit}")"
if [ "${kbase}" = "samba4kinit" ]; then
	# HEIMDAL
	OPTION_RENEWABLE="--renewable"
	OPTION_RENEW_TICKET="--renew"
	OPTION_ENTERPRISE_NAME="--enterprise"
	OPTION_CANONICALIZATION=""
	OPTION_WINDOWS="--windows"
	OPTION_SERVICE="-S"
else
	# MIT
	OPTION_RENEWABLE="-r 1h"
	OPTION_RENEW_TICKET="-R"
	OPTION_ENTERPRISE_NAME="-E"
	OPTION_CANONICALIZATION="-C"
	OPTION_WINDOWS=""
	OPTION_SERVICE="-S"
fi

TEST_USER="$(mktemp -u kinittest-XXXXXX)"
UNC="//${SERVER}/tmp"

ADMIN_LDBMODIFY_CONFIG="-H ldap://${SERVER} -U${USERNAME}%${PASSWORD}"
export ADMIN_LDBMODIFY_CONFIG

KRB5CCNAME_PATH="${PREFIX}/tmpccache"
KRB5CCNAME="FILE:${KRB5CCNAME_PATH}"
export KRB5CCNAME
rm -rf "${KRB5CCNAME_PATH}"

testit "reset password policies beside of minimum password age of 0 days" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" domain passwordsettings set \
	"${ADMIN_LDBMODIFY_CONFIG}" \
	--complexity=default \
	--history-length=default \
	--min-pwd-length=default \
	--min-pwd-age=0 \
	--max-pwd-age=default || \
	failed=$((failed + 1))

###########################################################
### Test kinit defaults
###########################################################

testit "kinit with password (initial)" \
	kerberos_kinit "${samba_kinit}" "${USERNAME}@${REALM}" "${PASSWORD}" \
	"${OPTION_RENEWABLE}" || \
	failed=$((failed + 1))
test_smbclient "Test login with user kerberos ccache" \
	"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

testit "kinit renew ticket (initial)" \
	"${samba_kinit}" ${OPTION_RENEW_TICKET} || \
	failed=$((failed + 1))

test_smbclient "Test login with kerberos ccache (initial)" \
	"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"

###########################################################
### Test kinit with enterprise principal
###########################################################

testit "kinit with password (enterprise style)" \
	kerberos_kinit "${samba_kinit}" \
	"${USERNAME}@${REALM}" "${PASSWORD}" "${OPTION_ENTERPRISE_NAME}" \
	"${OPTION_RENEWABLE}" || \
	failed=$((failed + 1))

test_smbclient "Test login with user kerberos ccache (enterprise style)" \
	"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

testit "kinit renew ticket (enterprise style)" \
	"${samba_kinit}" ${OPTION_RENEW_TICKET} || \
	failed=$((failed + 1))

test_smbclient "Test login with kerberos ccache (enterprise style)" \
	"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"

###########################################################
### Tests with kinit windows
###########################################################

# HEIMDAL ONLY
if [ "${kbase}" = "samba4kinit" ]; then
	testit "kinit with password (windows style)" \
		kerberos_kinit "${samba_kinit}" \
		"${USERNAME}@${REALM}" "${PASSWORD}" \
		"${OPTION_RENEWABLE}" "${OPTION_WINDOWS}" || \
		failed=$((failed + 1))

	test_smbclient "Test login with kerberos ccache (windows style)" \
		"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
		failed=$((failed + 1))

	testit "kinit renew ticket (windows style)" \
		"${samba_kinit}" ${OPTION_RENEW_TICKET} || \
		failed=$((failed + 1))

	test_smbclient "Test login with kerberos ccache (windows style)" \
		"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
		failed=$((failed + 1))

	rm -f "${KRB5CCNAME_PATH}"
fi # HEIMDAL ONLY

###########################################################
### Tests with kinit default again
###########################################################

testit "kinit with password (default)" \
	kerberos_kinit "${samba_kinit}" "${USERNAME}@${REALM}" "${PASSWORD}" || \
	failed=$((failed + 1))

testit "check time with kerberos ccache (default)" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" time "${SERVER}" \
	"${CONFIGURATION}" --use-krb5-ccache="${KRB5CCNAME}" "$@" || \
	failed=$((failed + 1))

USERPASS="testPass@12%"

testit "add user with kerberos ccache" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" user create \
	"${TEST_USER}" "${USERPASS}" \
	"${CONFIGURATION}" --use-krb5-ccache="${KRB5CCNAME}" "$@" || \
	failed=$((failed + 1))

echo "Getting defaultNamingContext"
BASEDN=$(${ldbsearch} --basedn='' -H "ldap://${SERVER}" --scope=base \
	DUMMY=x defaultNamingContext | awk '/defaultNamingContext/ {print $2}')


TEST_UPN="$(mktemp -u test-XXXXXX)@${REALM}"
cat >"${PREFIX}/tmpldbmodify" <<EOF
dn: cn=${TEST_USER},cn=users,${BASEDN}
changetype: modify
add: servicePrincipalName
servicePrincipalName: host/${TEST_USER}
replace: userPrincipalName
userPrincipalName: ${TEST_UPN}
EOF

testit "modify servicePrincipalName and userPrincpalName" \
	"${VALGRIND}" "${ldbmodify}" -H "ldap://${SERVER}" "${PREFIX}/tmpldbmodify" \
	--use-krb5-ccache="${KRB5CCNAME}" "$@" || \
	failed=$((failed + 1))

testit "set user password with kerberos ccache" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" user setpassword "${TEST_USER}" \
	--newpassword="${USERPASS}" "${CONFIGURATION}" \
	--use-krb5-ccache="${KRB5CCNAME}" "$@" || \
	failed=$((failed + 1))

testit "enable user with kerberos cache" \
	"${VALGRIND}" "${PYTHON}" "${samba_enableaccount}" "${TEST_USER}" \
	-H "ldap://$SERVER" --use-krb5-ccache="${KRB5CCNAME}" "$@" || \
	failed=$((failed + 1))

testit "kinit with new user password" \
	kerberos_kinit "${samba_kinit}" "${TEST_USER}" "${USERPASS}" || \
	failed=$((failed + 1))

test_smbclient "Test login with new user kerberos ccache" \
	"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"

###########################################################
### Test kinit after changing password with samba-tool
###########################################################

NEW_USERPASS="testPaSS@34%"
testit "change user password with 'samba-tool user password' (rpc)" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" user password \
	-W"${DOMAIN}" -U"${TEST_USER}%${USERPASS}" "${CONFIGURATION}" \
	--newpassword="${NEW_USERPASS}" \
	--use-kerberos=off "$@" || \
	failed=$((failed + 1))

testit "kinit with user password (after rpc password change)" \
	kerberos_kinit "${samba_kinit}" \
	"${TEST_USER}@${REALM}" "${NEW_USERPASS}" || \
	failed=$((failed + 1))

test_smbclient "Test login with user kerberos (after rpc password change)" \
	"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

USERPASS="${NEW_USERPASS}"

rm -f "${KRB5CCNAME_PATH}"

###########################################################
### Test kinit with UPN
###########################################################

testit "kinit with new (NT-Principal style) using UPN" \
	kerberos_kinit "${samba_kinit}" "${TEST_UPN}" "${USERPASS}" || \
	failed=$((failed + 1))

test_smbclient "Test login with user kerberos ccache from NT UPN" \
	"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"

testit "kinit with new (enterprise style) using UPN" \
	kerberos_kinit "${samba_kinit}" "${TEST_UPN}" "${USERPASS}" \
	${OPTION_ENTERPRISE_NAME} || \
	failed=$((failed + 1))

test_smbclient "Test login with user kerberos ccache from enterprise UPN" \
	"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"

# HEIMDAL ONLY
if [ "${kbase}" = "samba4kinit" ]; then
	testit "kinit with new (windows style) using UPN" \
		kerberos_kinit "${samba_kinit}" "${TEST_UPN}" "${USERPASS}" \
		${OPTION_WINDOWS} || \
		failed=$((failed + 1))

	test_smbclient "Test login with user kerberos ccache with (windows style) UPN" \
		"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
		failed=$((failed + 1))

	rm -f "${KRB5CCNAME_PATH}"
fi # HEIMDAL ONLY

###########################################################
### Tests with SPN
###########################################################

DNSDOMAIN=$(echo "${REALM}" | tr '[:upper:]' '[:lower:]')
testit "kinit with password (SPN)" \
	kerberos_kinit "${samba_kinit}" \
	"http/testupnspn.${DNSDOMAIN}" "${PASSWORD}" || \
	failed=$((failed + 1))

test_smbclient "Test login with kerberos ccache (SPN)" \
	"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"

###########################################################
### Test kinit with canonicalization
###########################################################

upperusername=$(echo "${USERNAME}" | tr '[:lower:]' '[:upper:]')
testit "kinit with canonicalize and service" \
	kerberos_kinit "${samba_kinit}" "${upperusername}@${REALM}" "${PASSWORD}" \
	${OPTION_CANONICALIZATION} \
	${OPTION_SERVICE} "kadmin/changepw@${REALM}" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"

###########################################################
### Test kinit with user credentials and changed realm
###########################################################

testit "kinit with password (default)" \
	kerberos_kinit "${samba_kinit}" "${USERNAME}@${REALM}" "${PASSWORD}" || \
	failed=$((failed + 1))

cat >"${PREFIX}/tmpldbmodify" <<EOF
dn: cn=${TEST_USER},cn=users,$BASEDN
changetype: modify
replace: userPrincipalName
userPrincipalName: ${TEST_UPN}.org
EOF

testit "modify userPrincipalName to be a different domain" \
	"${VALGRIND}" "${ldbmodify}" "${ADMIN_LDBMODIFY_CONFIG}" \
	"${PREFIX}/tmpldbmodify" "${PREFIX}/tmpldbmodify" \
	--use-krb5-ccache="${KRB5CCNAME}" "$@" || \
	failed=$((failed + 1))

testit "kinit with new (enterprise style) using UPN" \
	kerberos_kinit "${samba_kinit}" "${TEST_UPN}.org" "${USERPASS}" \
	${OPTION_ENTERPRISE_NAME} || failed=$((failed + 1))

test_smbclient "Test login with user kerberos ccache from enterprise UPN" \
	"ls" "${UNC}" \
	--use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"

###########################################################
### Test password change with kpasswd
###########################################################

testit "kinit with user password" \
	kerberos_kinit "${samba_kinit}" "${TEST_USER}@$REALM" "${USERPASS}" || \
	failed=$((failed + 1))

test_smbclient "Test login with user kerberos ccache" \
	"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

NEWUSERPASS=testPaSS@56%

if [ "${kbase}" = "samba4kinit" ]; then
	# HEIMDAL
	cat >"${PREFIX}/tmpkpasswdscript" <<EOF
expect Password
password ${USERPASS}\n
expect New password
send ${NEWUSERPASS}\n
expect Verify password
send ${NEWUSERPASS}\n
expect Success
EOF

else
	# MIT
	cat >"${PREFIX}/tmpkpasswdscript" <<EOF
expect Password for
password ${USERPASS}\n
expect Enter new password
send ${NEWUSERPASS}\n
expect Enter it again
send ${NEWUSERPASS}\n
expect Password changed
EOF
fi

testit "change user password with kpasswd" \
	"${samba_texpect}" "${PREFIX}/tmpkpasswdscript" \
	"${samba_kpasswd}" "${TEST_USER}@$REALM" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"

USERPASS="${NEWUSERPASS}"

testit "kinit with user password (after kpasswd)" \
	kerberos_kinit "${samba_kinit}" \
	"${TEST_USER}@${REALM}" "${USERPASS}" || \
	failed=$((failed + 1))

test_smbclient "Test login with user kerberos ccache (after kpasswd)" \
	"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"

###########################################################
### TODO Test set password with kpasswd
###########################################################

# This is not implemented in kpasswd

###########################################################
### Test password expiry
###########################################################

	cat >"${PREFIX}/tmpldbmodify" <<EOF
dn: cn=${TEST_USER},cn=users,${BASEDN}
changetype: modify
replace: pwdLastSet
pwdLastSet: 0
EOF

	NEWUSERPASS=testPaSS@78%

	testit "modify pwdLastSet" \
		"${VALGRIND}" "${ldbmodify}" "${ADMIN_LDBMODIFY_CONFIG}" \
		"${PREFIX}/tmpldbmodify" "${PREFIX}/tmpldbmodify" \
		--use-krb5-ccache="${KRB5CCNAME}" "$@" || \
		failed=$((failed + 1))

if [ "${kbase}" = "samba4kinit" ]; then
	# HEIMDAL branch
	cat >"${PREFIX}/tmpkinituserpassscript" <<EOF
expect ${TEST_USER}@$REALM's Password
send ${USERPASS}\n
expect Password has expired
expect New password
send ${NEWUSERPASS}\n
expect Repeat new password
send ${NEWUSERPASS}\n
EOF
else
	# MIT branch
	cat >"${PREFIX}/tmpkinituserpassscript" <<EOF
expect Password for
send ${USERPASS}\n
expect Password expired.  You must change it now.
expect Enter new password
send ${NEWUSERPASS}\n
expect Enter it again
send ${NEWUSERPASS}\n
EOF

fi # END MIT ONLY

testit "kinit with user password for expired password" \
	"${samba_texpect}" "$PREFIX/tmpkinituserpassscript" \
	"${samba_kinit}" "${TEST_USER}@$REALM" || \
	failed=$((failed + 1))

test_smbclient "Test login with user kerberos ccache" \
	"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

USERPASS="${NEWUSERPASS}"

testit "kinit with user password" \
	kerberos_kinit "${samba_kinit}" \
	"${TEST_USER}@${REALM}" "${USERPASS}" || \
	failed=$((failed + 1))

test_smbclient "Test login with user kerberos ccache" \
	"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

###########################################################
### Test login with lowercase realm
###########################################################

KRB5CCNAME_PATH="$PREFIX/tmpccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME

rm -rf "${KRB5CCNAME_PATH}"

testit "kinit with user password" \
	kerberos_kinit "${samba_kinit}" "${TEST_USER}@${REALM}" "${USERPASS}" || \
	failed=$((failed + 1))

lowerrealm=$(echo "${REALM}" | tr '[:upper:]' '[:lower:]')
test_smbclient "Test login with user kerberos lowercase realm" \
	"ls" "${UNC}" --use-kerberos=required \
	-U"${TEST_USER}@${lowerrealm}%${NEWUSERPASS}" || \
	failed=$((failed + 1))

test_smbclient "Test login with user kerberos lowercase realm 2" \
	"ls" "${UNC}" --use-kerberos=required \
	-U"${TEST_USER}@${REALM}%${NEWUSERPASS}" --realm="${lowerrealm}" || \
	failed=$((failed + 1))

testit "del user with kerberos ccache" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" user delete \
	"${TEST_USER}" "${CONFIGURATION}" \
	--use-krb5-ccache="${KRB5CCNAME}" "$@" || \
	failed=$((failed + 1))

###########################################################
### Test login with machine account
###########################################################

rm -f "${KRB5CCNAME_PATH}"

testit "kinit with machineaccountccache script" \
	"${PYTHON}" "${machineaccountccache}" "${CONFIGURATION}" \
	"${KRB5CCNAME}" || \
	failed=$((failed + 1))

test_smbclient "Test machine account login with kerberos ccache" \
	"ls" "${UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

testit "reset password policies" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" domain passwordsettings set \
	"${ADMIN_LDBMODIFY_CONFIG}" \
	--complexity=default \
	--history-length=default \
	--min-pwd-length=default \
	--min-pwd-age=default \
	--max-pwd-age=default || \
	failed=$((failed + 1))

###########################################################
### Test basic s4u2self request
###########################################################

# MIT ONLY
if [ "${kbase}" = "kinit" ]; then

# Use previous acquired machine creds to request a ticket for self.
# We expect it to fail for now.
MACHINE_ACCOUNT="$(hostname -s | tr '[:lower:]' '[:upper:]')\$@${REALM}"

${samba_kvno} -U"${MACHINE_ACCOUNT}" "${MACHINE_ACCOUNT}"

# But we expect the KDC to be up and running still
testit "kinit with machineaccountccache after s4u2self" \
	"${machineaccountccache}" "${CONFIGURATION}" "${KRB5CCNAME}" || \
	failed=$((failed + 1))

fi # END MIT ONLY

### Cleanup

rm -f "${KRB5CCNAME_PATH}"
rm -f "${PREFIX}/tmpkinituserpassscript"
rm -f "${PREFIX}/tmpkinitscript"
rm -f "${PREFIX}/tmpkpasswdscript"

exit $failed
