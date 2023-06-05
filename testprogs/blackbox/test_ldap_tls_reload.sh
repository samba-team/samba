#!/bin/bash
#

if [ $# -ne 3 ]; then
	cat <<EOF
Usage: test_ldap_tls_reload.sh PREFIX TLSDIR SERVER
EOF
	exit 1
fi

PREFIX=$1
TLSDIR=$2
SERVER=$3

. $(dirname $0)/subunit.sh
. "$(dirname "${0}")/common_test_fns.inc"

ldbsearch="${VALGRIND} $(system_or_builddir_binary ldbsearch "${BINDIR}")"
smbcontrol="${VALGRIND} ${BINDIR}/smbcontrol"

rm -rf "$PREFIX/ldap_tls_reload"

store_cert() {
	FILE=$1
	gnutls-cli --save-cert="$FILE" --no-ca-verification --verify-hostname=$SERVER --port 636 $SERVER < /dev/null
	return $?
}

delete_certs() {
	ls "${TLSDIR}/"*.pem
	rm -v "${TLSDIR}/ca.pem" "${TLSDIR}/cert.pem" "${TLSDIR}/key.pem"
	return $?
}

reload_certs() {
	$smbcontrol ldap_server reload-certs
	return $?
}

testit "mkdir $PREFIX/ldap_tls_reload" mkdir $PREFIX/ldap_tls_reload || failed=$(expr $failed + 1)

testit "currentTime 1" $ldbsearch --basedn='' -H ldaps://$SERVER --scope=base currentTime || failed=$(expr $failed + 1)

testit "store cert output 1a" store_cert $PREFIX/ldap_tls_reload/cert1a.pem || failed=$(expr $failed + 1)

testit "delete certs" delete_certs || failed=$(expr $failed + 1)

testit "store cert output 1b" store_cert $PREFIX/ldap_tls_reload/cert1b.pem || failed=$(expr $failed + 1)

testit "check cert1a == cert1b" cmp $PREFIX/ldap_tls_reload/cert1a.pem $PREFIX/ldap_tls_reload/cert1b.pem || failed=$(expr $failed + 1)

testit "reload certs " reload_certs || failed=$(expr $failed + 1)

testit "sleep 10" sleep 10 || failed=$(expr $failed + 1)

testit "store cert output 2" store_cert $PREFIX/ldap_tls_reload/cert2.pem || failed=$(expr $failed + 1)

testit_expect_failure "check cert1a != cert2" cmp $PREFIX/ldap_tls_reload/cert1a.pem $PREFIX/ldap_tls_reload/cert2.pem || failed=$(expr $failed + 1)

testit "currentTime 2" $ldbsearch $CONFIGURATION --basedn='' -H ldaps://$SERVER --scope=base currentTime || failed=$(expr $failed + 1)

rm -rf "$PREFIX/ldap_tls_reload"

testok $0 $failed
