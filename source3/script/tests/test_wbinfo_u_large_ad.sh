#!/bin/sh

LDBMODIFY="$VALGRIND ${LDBMODIFY:-$BINDIR/ldbmodify} $CONFIGURATION"
LDBSEARCH="$VALGRIND ${LDBSEARCH:-$BINDIR/ldbsearch} $CONFIGURATION"
WBINFO="$VALGRIND ${WBINFO:-$BINDIR/wbinfo} $CONFIGURATION"

NUM_USERS=1234

BASE_DN=$($LDBSEARCH -H ldap://$DC_SERVER -b "" --scope=base defaultNamingContext | awk '/^defaultNamingContext/ {print $2}')

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

seq -w 1 "$NUM_USERS" |
    xargs -INUM echo -e "dn:cn=large_ad_NUM,cn=users,$BASE_DN\nchangetype:add\nobjectclass:user\nsamaccountname:large_ad_NUM\n" |
    $LDBMODIFY -H ldap://$DC_SERVER -U "$DOMAIN\Administrator%$DC_PASSWORD"

testit_grep_count \
    "Make sure $NUM_USERS $DOMAIN users are returned" \
    "$DOMAIN/large_ad_" \
    "$NUM_USERS" \
    ${WBINFO} -u || failed=$(expr $failed + 1)

seq -w 1 "$NUM_USERS" |
    xargs -INUM echo -e "dn:cn=large_ad_NUM,cn=users,$BASE_DN\nchangetype:delete\n" |
    $LDBMODIFY -H ldap://$DC_SERVER -U "$DOMAIN\Administrator%$DC_PASSWORD"

testok $0 $failed
