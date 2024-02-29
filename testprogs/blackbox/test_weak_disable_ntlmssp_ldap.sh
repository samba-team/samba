#!/bin/sh
# Blackbox tests for diabing NTLMSSP for ldap client connections
# Copyright (c) 2022      Pavel Filipenský <pfilipen@redhat.com>

if [ $# -lt 2 ]; then
	cat <<EOF
Usage: $0 USERNAME PASSWORD
EOF
	exit 1
fi

USERNAME=$1
PASSWORD=$2
shift 2

failed=0
. $(dirname $0)/subunit.sh

samba_testparm="$BINDIR/testparm"
samba_net="$BINDIR/net"

unset GNUTLS_FORCE_FIPS_MODE

# Checks that testparm reports: Weak crypto is allowed
testit_grep "testparm.with-weak" "Weak crypto is allowed" $samba_testparm --suppress-prompt $SMB_CONF_PATH 2>&1 || failed=$(expr $failed + 1)

# We should be allowed to use NTLM for connecting
testit "net_ads_search.ntlm.with-weak" $samba_net ads search --use-kerberos=off '(objectCategory=group)' sAMAccountName -U${USERNAME}%${PASSWORD} || failed=$(expr $failed + 1)

GNUTLS_FORCE_FIPS_MODE=1
export GNUTLS_FORCE_FIPS_MODE

# Checks that testparm reports: Weak crypto is disallowed
testit_grep "testparm.without-weak" "Weak crypto is disallowed" $samba_testparm --suppress-prompt $SMB_CONF_PATH 2>&1 || failed=$(expr $failed + 1)

# We should not be allowed to use NTLM for connecting
testit_expect_failure_grep \
	"net_ads_search.ntlm.without-weak" \
	"ads_sasl_spnego_gensec_bind.*failed.for.ldap/.*user.*${USERNAME}.:.An.invalid.parameter." \
	$samba_net ads search -d10 --use-kerberos=off '(objectCategory=group)' sAMAccountName -U${USERNAME}%${PASSWORD} || failed=$(expr $failed + 1)

unset GNUTLS_FORCE_FIPS_MODE

testok $0 $failed
