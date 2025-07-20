#!/bin/sh

if [ $# -lt 5 ]; then
	cat <<EOF
Usage: test_net_ads_kerberos.sh USERNAME REALM PASSWORD PREFIX
EOF
	exit 1
fi

USERNAME="$1"
REALM="$2"
PASSWORD="$3"
PREFIX="$4"
shift 4
ADDARGS="$*"

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir"/subunit.sh

mkdir -p "$PREFIX"/private
PACFILE=$PREFIX/private/pacsave.$$

KRB5CCNAME_PATH="$PREFIX/net_ads_kerberos_krb5ccache"
rm -f "$KRB5CCNAME_PATH"

KRB5CCNAME="FILE:$KRB5CCNAME_PATH"


#################################################
## Test "net ads kerberos kinit" variants
#################################################

testit "net_ads_kerberos_kinit" \
	"$VALGRIND" "$BINDIR"/net ads kerberos kinit \
	-U"$USERNAME"%"$PASSWORD" "$ADDARGS" \
	|| failed=$((failed + 1))

export KRB5CCNAME="$KRB5CCNAME_PATH"
testit "net_ads_kerberos_kinit (KRB5CCNAME env set)" \
	"$VALGRIND" "$BINDIR"/net ads kerberos kinit \
	-U"$USERNAME"%"$PASSWORD" "$ADDARGS" \
	|| failed=$((failed + 1))
unset KRB5CCNAME
rm -f "$KRB5CCNAME_PATH"

# --use-krb5-ccache is not working
#testit "net_ads_kerberos_kinit (with --use-krb5-ccache)" \
#	$VALGRIND $BINDIR/net ads kerberos kinit \
#	-U$USERNAME%$PASSWORD $ADDARGS \
#	--use-krb5-ccache=${KRB5CCNAME} \
#	|| failed=$((failed + 1))

testit "net_ads_kerberos_kinit (-P)" \
	"$VALGRIND" "$BINDIR"/net ads kerberos kinit \
	-P "$ADDARGS" \
	|| failed=$((failed + 1))

export KRB5CCNAME="$KRB5CCNAME_PATH"
testit "net_ads_kerberos_kinit (-P and KRB5CCNAME env set)" \
	"$VALGRIND" "$BINDIR"/net ads kerberos kinit \
	-P "$ADDARGS" \
	|| failed=$((failed + 1))
unset KRB5CCNAME
rm -f "$KRB5CCNAME_PATH"

# --use-krb5-ccache is not working
#testit "net_ads_kerberos_kinit (-P with --use-krb5-ccache)" \
#	$VALGRIND $BINDIR/net ads kerberos kinit \
#	-P $ADDARGS \
#	--use-krb5-ccache=${KRB5CCNAME} \
#	|| failed=$((failed + 1))


#################################################
## Test "net ads kerberos renew" variants
#################################################

#testit "net_ads_kerberos_renew" \
#	$VALGRIND $BINDIR/net ads kerberos renew \
#	-U$USERNAME%$PASSWORD $ADDARGS \
#	|| failed=$((failed + 1))
#
#export KRB5CCNAME=$KRB5CCNAME_PATH
#testit "net_ads_kerberos_renew (KRB5CCNAME env)" \
#	$VALGRIND $BINDIR/net ads kerberos renew \
#	-U$USERNAME%$PASSWORD $ADDARGS \
#	|| failed=$((failed + 1))
#unset KRB5CCNAME
#rm -f $KRB5CCNAME_PATH
#
# renew only succeeds with pre-kinit
export KRB5CCNAME="$KRB5CCNAME_PATH"
testit "net_ads_kerberos_kinit (KRB5CCNAME env set)" \
	"$VALGRIND" "$BINDIR"/net ads kerberos kinit \
	-U"$USERNAME"%"$PASSWORD" "$ADDARGS" \
	|| failed=$((failed + 1))

testit "net_ads_kerberos_renew" \
	"$VALGRIND" "$BINDIR"/net ads kerberos renew \
	-U"$USERNAME"%"$PASSWORD" "$ADDARGS" \
	|| failed=$((failed + 1))
unset KRB5CCNAME
rm -f "$KRB5CCNAME_PATH"


#################################################
## Test "net ads kerberos pac" variants
#################################################

testit "net_ads_kerberos_pac_dump" \
	"$VALGRIND" "$BINDIR"/net ads kerberos pac dump \
	-U"$USERNAME"%"$PASSWORD" "$ADDARGS" \
	|| failed=$((failed + 1))

testit "net_ads_kerberos_pac_dump (-P)" \
	"$VALGRIND" "$BINDIR"/net ads kerberos pac dump \
	-P "$ADDARGS" \
	|| failed=$((failed + 1))

IMPERSONATE_PRINC="alice@$REALM"

#testit "net_ads_kerberos_pac_dump (impersonate)" \
#	$VALGRIND $BINDIR/net ads kerberos pac dump \
#	-U$USERNAME%$PASSWORD \
#	impersonate=$IMPERSONATE_PRINC $ADDARGS \
#	|| failed=$((failed + 1))

testit "net_ads_kerberos_pac_dump (impersonate and -P)" \
	"$VALGRIND" "$BINDIR"/net ads kerberos pac dump \
	-P \
	impersonate="$IMPERSONATE_PRINC" "$ADDARGS" \
	|| failed=$((failed + 1))

# no clue why this doesn't work...
#
#testit_expect_failure "net_ads_kerberos_pac_save (without filename)"
#	$VALGRIND $BINDIR/net ads kerberos pac save \
#	-U$USERNAME%$PASSWORD $ADDARGS \
#	|| failed=$((failed + 1))

testit "net_ads_kerberos_pac_save" \
	"$VALGRIND" "$BINDIR"/net ads kerberos pac save \
	-U"$USERNAME"%"$PASSWORD" "$ADDARGS" \
	filename="$PACFILE" \
	|| failed=$((failed + 1))

rm -f "$PACFILE"

testit "net_ads_kerberos_pac_save (-P)" \
	"$VALGRIND" "$BINDIR"/net ads kerberos pac save \
	-P "$ADDARGS" \
	filename="$PACFILE" \
	|| failed=$((failed + 1))

rm -f "$PACFILE"
rm -f "$KRB5CCNAME_PATH"

testok "$0" "$failed"
