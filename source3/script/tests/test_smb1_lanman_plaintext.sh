#!/bin/sh

if [ $# -lt 3 ]; then
	cat <<EOF
Usage: test_smb1_lanman_plaintext.sh SERVER USERNAME PASSWORD
EOF
	exit 1
fi

# This is used by test_smbclient()
# shellcheck disable=2034
smbclient=$1
SERVER=$2
USERNAME=$3
PASSWORD=$4
shift 4

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh
. $incdir/common_test_fns.inc

failed=0

opt="-W ${SERVER} -U${USERNAME}%${PASSWORD}"

# check
test_smbclient "test_default" "ls" "//$SERVER/tmp" $opt || failed=$(expr $failed + 1)

global_inject_conf=$(dirname $SMB_CONF_PATH)/global_inject.conf
cat > $global_inject_conf << _EOF
    server min protocol = LANMAN1
    client min protocol = LANMAN1
    lanman auth = no
_EOF

opt="--option=clientminprotocol=LANMAN1 -m LANMAN1 -c ls --option=clientNTLMv2auth=no --option=clientlanmanauth=yes -W ${SERVER} -U${USERNAME}%${PASSWORD}"
test_smbclient_expect_failure "test_lm_fail" "ls" "//$SERVER/tmp" $opt || failed=$(expr $failed + 1)

cat > $global_inject_conf << _EOF
    server min protocol = LANMAN1
    client min protocol = LANMAN1
    lanman auth = yes
    ntlm auth = yes
_EOF

test_smbclient "test_lm_ok" "ls" "//$SERVER/tmp" $opt || failed=$(expr $failed + 1)

cat > $global_inject_conf << _EOF
    server min protocol = LANMAN1
    client min protocol = LANMAN1
    lanman auth = yes
    ntlm auth = yes
    encrypt passwords = no
_EOF

test_smbclient_expect_failure "test_plaintext_fail_local" "ls" "//$SERVER/tmp" $opt || failed=$(expr $failed + 1)

opt="--option=clientminprotocol=LANMAN1 -m LANMAN1 -c ls --option=clientNTLMv2auth=no --option=clientlanmanauth=yes --option=clientplaintextauth=yes -W ${SERVER} -U${USERNAME}%${PASSWORD}"
test_smbclient "test_plaintext_ok" "ls" "//$SERVER/tmp" $opt || failed=$(expr $failed + 1)

echo '' >$global_inject_conf

testok $0 $failed
