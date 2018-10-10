#!/bin/sh
# Copyright (C) 2015 Stefan Metzmacher <metze@samba.org>

if [ $# -lt 12 ]; then
cat <<EOF
Usage: $# test_trust_utils.sh SERVER USERNAME PASSWORD REALM DOMAIN TRUST_USERNAME TRUST_PASSWORD TRUST_REALM TRUST_DOMAIN PREFIX TYPE
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
REALM=$4
DOMAIN=$5
shift 5
TRUST_SERVER=$1
TRUST_USERNAME=$2
TRUST_PASSWORD=$3
TRUST_REALM=$4
TRUST_DOMAIN=$5
shift 5
PREFIX=$1
TYPE=$2
shift 2
failed=0

samba4bindir="$BINDIR"

samba_tool="$samba4bindir/samba-tool"

. `dirname $0`/subunit.sh

CREDS="${DOMAIN}\\${USERNAME}%${PASSWORD}"
TRUST_CREDS="${TRUST_DOMAIN}\\${TRUST_USERNAME}%${TRUST_PASSWORD}"
TRUST_SERVER_CREDS_ARGS="--local-dc-ipaddress ${TRUST_SERVER} --local-dc-username ${TRUST_CREDS}"

list="$VALGRIND $PYTHON $samba_tool domain trust list"
testit "list domains default" $list || failed=`expr $failed + 1`
testit "list domains reverse" $list ${TRUST_SERVER_CREDS_ARGS} || failed=`expr $failed + 1`

show="$VALGRIND $PYTHON $samba_tool domain trust show"
testit "show domains default realm" $show ${TRUST_REALM} || failed=`expr $failed + 1`
testit "show domains reverse realm" $show ${REALM} ${TRUST_SERVER_CREDS_ARGS} || failed=`expr $failed + 1`
testit "show domains default netbios" $show ${TRUST_DOMAIN} || failed=`expr $failed + 1`
testit "show domains reverse netbios" $show ${DOMAIN} ${TRUST_SERVER_CREDS_ARGS} || failed=`expr $failed + 1`

validate="$VALGRIND $PYTHON $samba_tool domain trust validate"
testit "validate trust default both" $validate ${TRUST_REALM} -U${TRUST_CREDS}|| failed=`expr $failed + 1`
testit "validate trust default local" $validate ${TRUST_REALM} --validate-location=local || failed=`expr $failed + 1`
testit "validate trust reverse both" $validate ${REALM} ${TRUST_SERVER_CREDS_ARGS} -U${CREDS} || failed=`expr $failed + 1`
testit "validate trust reverse local" $validate ${REALM} ${TRUST_SERVER_CREDS_ARGS} --validate-location=local || failed=`expr $failed + 1`

namespaces="$VALGRIND $PYTHON $samba_tool domain trust namespaces"
testit "namespaces own default" $namespaces || failed=`expr $failed + 1`
testit "namespaces own reverse" $namespaces ${TRUST_SERVER_CREDS_ARGS} || failed=`expr $failed + 1`

DOMSID=`$namespaces | grep LocalDomain | sed -e 's!.*SID\[\(.*\)\].*!\1!'`
#testit_expect_failure "namespaces domsid default" echo ${DOMSID} || failed=`expr $failed + 1`

TRUST_DOMSID=`$namespaces ${TRUST_SERVER_CREDS_ARGS} | grep LocalDomain | sed -e 's!.*SID\[\(.*\)\].*!\1!'`
#testit_expect_failure "namespaces domsid reverse" echo ${TRUST_DOMSID} || failed=`expr $failed + 1`

if test x$TYPE = x"forest"; then
	testit "namespaces trust default realm 1" $namespaces ${TRUST_REALM} || failed=`expr $failed + 1`
	testit "namespaces trust reverse realm 1" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} || failed=`expr $failed + 1`

	testit "namespaces trust default domain 1" $namespaces ${TRUST_DOMAIN} || failed=`expr $failed + 1`
	testit "namespaces trust reverse domain 1" $namespaces ${DOMAIN} ${TRUST_SERVER_CREDS_ARGS} || failed=`expr $failed + 1`

	testit "namespaces own default add-upn-suffix 1" $namespaces --add-upn-suffix=default.test_trust_utils.example.com || failed=`expr $failed + 1`
	testit "namespaces own reverse add-upn-suffix 1" $namespaces ${TRUST_SERVER_CREDS_ARGS} --add-upn-suffix=reverse.test_trust_utils.example.com || failed=`expr $failed + 1`

	testit "namespaces own default add-upn-suffix 2" $namespaces --add-upn-suffix=${TRUST_REALM} || failed=`expr $failed + 1`
	testit "namespaces own reverse add-upn-suffix 2" $namespaces ${TRUST_SERVER_CREDS_ARGS} --add-upn-suffix=${REALM} || failed=`expr $failed + 1`

	testit "namespaces own default add-spn-suffix 1" $namespaces --add-spn-suffix=spn.test_trust_utils.example.com || failed=`expr $failed + 1`
	testit "namespaces own reverse add-spn-suffix 1" $namespaces ${TRUST_SERVER_CREDS_ARGS} --add-spn-suffix=spn.test_trust_utils.example.com || failed=`expr $failed + 1`

	testit "namespaces trust default check 1" $namespaces ${TRUST_REALM} --refresh=check || failed=`expr $failed + 1`
	testit "namespaces trust reverse check 1" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --refresh=check || failed=`expr $failed + 1`

	testit "namespaces trust default store 1" $namespaces ${TRUST_REALM} --refresh=store || failed=`expr $failed + 1`
	testit "namespaces trust reverse store 1" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --refresh=store || failed=`expr $failed + 1`

	testit "namespaces trust default enable-tln 1" $namespaces ${TRUST_REALM} --enable-tln=reverse.test_trust_utils.example.com || failed=`expr $failed + 1`
	testit "namespaces trust reverse enable-tln 1" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --enable-tln=default.test_trust_utils.example.com || failed=`expr $failed + 1`

	testit "namespaces trust default enable-tln 2" $namespaces ${TRUST_REALM} --enable-tln=spn.test_trust_utils.example.com || failed=`expr $failed + 1`
	testit "namespaces trust reverse enable-tln 2" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --enable-tln=spn.test_trust_utils.example.com || failed=`expr $failed + 1`

	testit "namespaces trust default enable-tln 3" $namespaces ${TRUST_REALM} --enable-tln=${TRUST_REALM} || failed=`expr $failed + 1`
	testit "namespaces trust reverse enable-tln 3" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --enable-tln=${REALM} || failed=`expr $failed + 1`

	testit "namespaces trust default disable-nb 1" $namespaces ${TRUST_REALM} --disable-nb=${TRUST_DOMAIN} || failed=`expr $failed + 1`
	testit "namespaces trust reverse disable-nb 1" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --disable-nb=${DOMAIN} || failed=`expr $failed + 1`

	testit "namespaces trust default disable-sid 1" $namespaces ${TRUST_REALM} --disable-sid=${TRUST_DOMSID} || failed=`expr $failed + 1`
	testit "namespaces trust reverse disable-sid 1" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --disable-sid=${DOMSID} || failed=`expr $failed + 1`

	testit "namespaces trust default disable-tln 1" $namespaces ${TRUST_REALM} --disable-tln=reverse.test_trust_utils.example.com || failed=`expr $failed + 1`
	testit "namespaces trust reverse disable-tln 1" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --disable-tln=default.test_trust_utils.example.com || failed=`expr $failed + 1`

	testit "namespaces trust default add-tln-ex 1" $namespaces ${TRUST_REALM} --add-tln-ex=exclude.${TRUST_REALM} || failed=`expr $failed + 1`
	testit "namespaces trust reverse add-tln-ex 1" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --add-tln-ex=exclude.${REALM} || failed=`expr $failed + 1`

	testit "namespaces trust default add-tln-ex 2" $namespaces ${TRUST_REALM} --add-tln-ex=sub.exclude.${TRUST_REALM} || failed=`expr $failed + 1`
	testit "namespaces trust reverse add-tln-ex 2" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --add-tln-ex=sub.exclude.${REALM} || failed=`expr $failed + 1`

	testit "namespaces trust default realm 2" $namespaces ${TRUST_REALM} || failed=`expr $failed + 1`
	testit "namespaces trust reverse realm 2" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} || failed=`expr $failed + 1`

	testit "namespaces trust default delete-tln-ex 1" $namespaces ${TRUST_REALM} --delete-tln-ex=exclude.${TRUST_REALM} || failed=`expr $failed + 1`
	testit "namespaces trust reverse delete-tln-ex 1" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --delete-tln-ex=exclude.${REALM} || failed=`expr $failed + 1`

	testit "namespaces trust default delete-tln-ex 2" $namespaces ${TRUST_REALM} --delete-tln-ex=sub.exclude.${TRUST_REALM} || failed=`expr $failed + 1`
	testit "namespaces trust reverse delete-tln-ex 2" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --delete-tln-ex=sub.exclude.${REALM} || failed=`expr $failed + 1`

	testit "namespaces own default delete-upn-suffix 1" $namespaces --delete-upn-suffix=default.test_trust_utils.example.com || failed=`expr $failed + 1`
	testit "namespaces own reverse delete-upn-suffix 1" $namespaces ${TRUST_SERVER_CREDS_ARGS} --delete-upn-suffix=reverse.test_trust_utils.example.com || failed=`expr $failed + 1`

	testit "namespaces own default delete-upn-suffix 2" $namespaces --delete-upn-suffix=${TRUST_REALM} || failed=`expr $failed + 1`
	testit "namespaces own reverse delete-upn-suffix 2" $namespaces ${TRUST_SERVER_CREDS_ARGS} --delete-upn-suffix=${REALM} || failed=`expr $failed + 1`

	testit "namespaces own default delete-spn-suffix 1" $namespaces --delete-spn-suffix=spn.test_trust_utils.example.com || failed=`expr $failed + 1`
	testit "namespaces own reverse delete-spn-suffix 1" $namespaces ${TRUST_SERVER_CREDS_ARGS} --delete-spn-suffix=spn.test_trust_utils.example.com || failed=`expr $failed + 1`

	testit "namespaces trust default enable-nb 1" $namespaces ${TRUST_REALM} --enable-nb=${TRUST_DOMAIN} || failed=`expr $failed + 1`
	testit "namespaces trust reverse enable-nb 1" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --enable-nb=${DOMAIN} || failed=`expr $failed + 1`

	testit "namespaces trust default enable-sid 1" $namespaces ${TRUST_REALM} --enable-sid=${TRUST_DOMSID} || failed=`expr $failed + 1`
	testit "namespaces trust reverse enable-sid 1" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --enable-sid=${DOMSID} || failed=`expr $failed + 1`

	testit "namespaces trust default reset final" $namespaces ${TRUST_REALM} --refresh=store --enable-all || failed=`expr $failed + 1`
	testit "namespaces trust reverse reset final" $namespaces ${REALM} ${TRUST_SERVER_CREDS_ARGS} --refresh=store --enable-all || failed=`expr $failed + 1`
fi

exit $failed
