#!/bin/sh
# Blackbox test for wbinfo
if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_wbinfo.sh DOMAIN USERNAME PASSWORD TARGET
EOF
exit 1;
fi

DOMAIN=$1
USERNAME=$2
PASSWORD=$3
TARGET=$4
shift 4

failed=0
samba4bindir="$BINDIR"
wbinfo="$VALGRIND $samba4bindir/wbinfo"

. `dirname $0`/../../testprogs/blackbox/subunit.sh

testfail() {
	name="$1"
	shift
	cmdline="$*"
	echo "test: $name"
	$cmdline
	status=$?
        if [ x$status = x0 ]; then
                echo "failure: $name"
        else
                echo "success: $name"
        fi
        return $status
}

knownfail() {
        name="$1"
        shift
        cmdline="$*"
        echo "test: $name"
        $cmdline
        status=$?
        if [ x$status = x0 ]; then
                echo "failure: $name [unexpected success]"
				status=1
        else
                echo "knownfail: $name"
				status=0
        fi
        return $status
}

KRB5CCNAME_PATH="$PREFIX/test_wbinfo_krb5ccache"
rm -f $KRB5CCNAME_PATH

KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME

# List users
testit "wbinfo -u against $TARGET" $wbinfo -u || failed=`expr $failed + 1`
# List groups
testit "wbinfo -g against $TARGET" $wbinfo -g || failed=`expr $failed + 1`
# Convert netbios name to IP
# Does not work yet
testit "wbinfo -N against $TARGET" $wbinfo -N $NETBIOSNAME || failed=`expr $failed + 1`
# Convert IP to netbios name
# Does not work yet
testit "wbinfo -I against $TARGET" $wbinfo -I $SERVER_IP || failed=`expr $failed + 1`

# Convert name to SID
testit "wbinfo -n against $TARGET" $wbinfo -n "$DOMAIN/$USERNAME" || failed=`expr $failed + 1`
admin_sid=`$wbinfo -n "$DOMAIN/$USERNAME" | cut -d " " -f1`
echo "$DOMAIN/$USERNAME resolved to $admin_sid"

testit "wbinfo -s $admin_sid against $TARGET" $wbinfo -s $admin_sid || failed=`expr $failed + 1`
admin_name=`$wbinfo -s $admin_sid | cut -d " " -f1| tr a-z A-Z`
echo "$admin_sid resolved to $admin_name"

tested_name=`echo $DOMAIN/$USERNAME | tr a-z A-Z`

echo "test: wbinfo -s check for sane mapping"
if test x$admin_name != x$tested_name; then
	echo "$admin_name does not match $tested_name"
	echo "failure: wbinfo -s check for sane mapping"
	failed=`expr $failed + 1`
else
	echo "success: wbinfo -s check for sane mapping"
fi

while read SID ; do
    read NAME

    testit "wbinfo -s $SID against $TARGET" $wbinfo -s $SID || failed=`expr $failed + 1`

    RESOLVED_NAME=`$wbinfo -s $SID | tr a-z A-Z`
    echo "$SID resolved to $RESOLVED_NAME"

    echo "test: wbinfo -s $SID against $TARGET"
    if test x"$RESOLVED_NAME" != x"$NAME" ; then
        echo "$RESOLVED_NAME does not match $NAME"
	echo "failure: wbinfo -s $SID against $TARGET"
	failed=`expr $failed + 1`
    else
        echo "success: wbinfo -s $SID against $TARGET"
    fi
done <<EOF
S-1-1-0
/EVERYONE 5
S-1-3-1
/CREATOR GROUP 5
S-1-5-1
NT AUTHORITY/DIALUP 5
EOF

testit "wbinfo -n on the returned name against $TARGET" $wbinfo -n $admin_name || failed=`expr $failed + 1`
test_sid=`$wbinfo -n $tested_name | cut -d " " -f1`

echo "test: wbinfo -n check for sane mapping"
if test x$admin_sid != x$test_sid; then
	echo "$admin_sid does not match $test_sid"
	echo "failure: wbinfo -n check for sane mapping"
	failed=`expr $failed + 1`
else
	echo "success: wbinfo -n check for sane mapping"
fi

echo "test: wbinfo -n NT Authority/Authenticated Users"
$wbinfo -n "NT Authority/Authenticated Users"
if [ $? -ne 0 ] ; then
    echo "failure: wbinfo -n NT Authority/Authenticated Users"
    failed=`expr $failed + 1`
else
    echo "success: wbinfo -n NT Authority/Authenticated Users"
fi

echo "test: wbinfo --group-info NT Authority/Authenticated Users"
$wbinfo --group-info "NT Authority/Authenticated Users"
if [ $? -ne 0 ] ; then
    echo "failure: wbinfo --group-info NT Authority/Authenticated Users"
    failed=`expr $failed + 1`
else
    echo "success: wbinfo --group-info NT Authority/Authenticated Users"
fi

testit "wbinfo -U against $TARGET" $wbinfo -U 30000 || failed=`expr $failed + 1`

echo "test: wbinfo -U check for sane mapping"
sid_for_30000=`$wbinfo -U 30000`
if test x$sid_for_30000 != "xS-1-22-1-30000"; then
	echo "uid 30000 mapped to $sid_for_30000, not S-1-22-1-30000"
	echo "failure: wbinfo -U check for sane mapping"
	failed=`expr $failed + 1`
else
	echo "success: wbinfo -U check for sane mapping"
fi

admin_uid=`$wbinfo -S $admin_sid`

testit "wbinfo -G against $TARGET" $wbinfo -G 30000 || failed=`expr $failed + 1`

echo "test: wbinfo -G check for sane mapping"
sid_for_30000=`$wbinfo -G 30000`
if test x$sid_for_30000 != "xS-1-22-2-30000"; then
        echo "gid 30000 mapped to $sid_for_30000, not S-1-22-2-30000"
	echo "failure: wbinfo -G check for sane mapping"
	failed=`expr $failed + 1`
else
	echo "success: wbinfo -G check for sane mapping"
fi

testit "wbinfo -S against $TARGET" $wbinfo -S "S-1-22-1-30000" || failed=`expr $failed + 1`

echo "test: wbinfo -S check for sane mapping"
uid_for_sid=`$wbinfo -S S-1-22-1-30000`
if test 0$uid_for_sid -ne 30000; then
	echo "S-1-22-1-30000 mapped to $uid_for_sid, not 30000"
	echo "failure: wbinfo -S check for sane mapping"
	failed=`expr $failed + 1`
else
	echo "success: wbinfo -S check for sane mapping"
fi

testfail "wbinfo -S against $TARGET using invalid SID" $wbinfo -S "S-1-22-2-30000" && failed=`expr $failed + 1`

testit "wbinfo -Y against $TARGET" $wbinfo -Y "S-1-22-2-30000" || failed=`expr $failed + 1`

echo "test: wbinfo -Y check for sane mapping"
gid_for_sid=`$wbinfo -Y S-1-22-2-30000`
if test 0$gid_for_sid -ne 30000; then
	echo "S-1-22-2-30000 mapped to $gid_for_sid, not 30000"
	echo "failure: wbinfo -Y check for sane mapping"
	failed=`expr $failed + 1`
else
	echo "success: wbinfo -Y check for sane mapping"
fi

testfail "wbinfo -Y against $TARGET using invalid SID" $wbinfo -Y "S-1-22-1-30000" && failed=`expr $failed + 1`

testit "wbinfo -t against $TARGET" $wbinfo -t || failed=`expr $failed + 1`

#didn't really work anyway
testit "wbinfo  --trusted-domains against $TARGET" $wbinfo --trusted-domains || failed=`expr $failed + 1`
testit "wbinfo --all-domains against $TARGET" $wbinfo --all-domains || failed=`expr $failed + 1`

testit "wbinfo --own-domain against $TARGET" $wbinfo --own-domain || failed=`expr $failed + 1`

echo "test: wbinfo --own-domain against $TARGET check output"
own_domain=`$wbinfo --own-domain`
if test x$own_domain = x$DOMAIN; then
	echo "success: wbinfo --own-domain against $TARGET check output"
else
	echo "Own domain reported as $own_domain instead of $DOMAIN"
	echo "failure: wbinfo --own-domain against $TARGET check output"
	failed=`expr $failed + 1`
fi

# this does not work
knownfail "wbinfo --sequence against $TARGET" $wbinfo --sequence

# this is stubbed out now
testit "wbinfo -D against $TARGET" $wbinfo -D $DOMAIN || failed=`expr $failed + 1`

testit "wbinfo -i against $TARGET" $wbinfo -i "$DOMAIN/$USERNAME" || failed=`expr $failed + 1`

echo "test: wbinfo --group-info against $TARGET"
gid=`$wbinfo --group-info "$DOMAIN/Domain users" | cut -d: -f3`
if test x$? = x0; then
	echo "success: wbinfo --group-info against $TARGET"
else
	echo "failure: wbinfo --group-info against $TARGET"
	failed=`expr $failed + 1`
fi

test_name="wbinfo -i against $TARGET"
subunit_start_test "$test_name"
passwd_line=`$wbinfo -i "$DOMAIN/$USERNAME"`
if test x$? = x0; then
	subunit_pass_test "$test_name"
else
	subunit_fail_test "$test_name"
	failed=`expr $failed + 1`
fi

test_name="confirm output of wbinfo -i against $TARGET"
subunit_start_test "$test_name"

# The full name (GECOS) is based on name (the RDN, in this case CN)
# and displayName in winbindd_ads, and is based only on displayName in
# winbindd_msrpc and winbindd_rpc.  Allow both versions.
if test "$TARGET" = "ad_member"; then
	expected1_line="$DOMAIN/administrator:*:$admin_uid:$gid:Administrator:/home/$DOMAIN/Domain Users/administrator:/bin/false"
	expected2_line="$DOMAIN/administrator:*:$admin_uid:$gid::/home/$DOMAIN/Domain Users/administrator:/bin/false"
else
	expected1_line="$DOMAIN/administrator:*:$admin_uid:$gid:Administrator:/home/$DOMAIN/administrator:/bin/false"
	expected2_line="$DOMAIN/administrator:*:$admin_uid:$gid::/home/$DOMAIN/administrator:/bin/false"
fi

if test "x$passwd_line" = "x$expected1_line" -o "x$passwd_line" = "x$expected2_line"; then
	subunit_pass_test "$test_name"
else
	echo "expected '$expected1_line' or '$expected2_line' got '$passwd_line'" | subunit_fail_test "$test_name"
	failed=`expr $failed + 1`
fi

test_name="wbinfo --uid-info against $TARGET"
subunit_start_test "$test_name"
passwd_line=`$wbinfo --uid-info=$admin_uid`
if test x$? = x0; then
	subunit_pass_test "$test_name"
else
	subunit_fail_test "$test_name"
	failed=`expr $failed + 1`
fi

test_name="confirm output of wbinfo --uid-info against $TARGET"
subunit_start_test "$test_name"
if test "x$passwd_line" = "x$expected1_line" -o "x$passwd_line" = "x$expected2_line"; then
	subunit_pass_test "$test_name"
else
	echo "expected '$expected1_line' or '$expected2_line' got '$passwd_line'" | subunit_fail_test "$test_name"
	failed=`expr $failed + 1`
fi

testfail "wbinfo --group-info against $TARGET with $USERNAME" $wbinfo --group-info $USERNAME && failed=`expr $failed + 1`

testit "wbinfo --gid-info against $TARGET" $wbinfo --gid-info $gid || failed=`expr $failed + 1`

testit "wbinfo -r against $TARGET" $wbinfo -r "$DOMAIN/$USERNAME" || failed=`expr $failed + 1`

testit "wbinfo --user-domgroups against $TARGET" $wbinfo --user-domgroups $admin_sid || failed=`expr $failed + 1`

testit "wbinfo --user-sids against $TARGET" $wbinfo --user-sids $admin_sid || failed=`expr $failed + 1`

testit "wbinfo -a against $TARGET with domain creds" $wbinfo -a "$DOMAIN/$USERNAME"%"$PASSWORD" || failed=`expr $failed + 1`

testit "wbinfo --getdcname against $TARGET" $wbinfo --getdcname=$DOMAIN

testit "wbinfo -p against $TARGET" $wbinfo -p || failed=`expr $failed + 1`

testit "wbinfo -K against $TARGET with domain creds" $wbinfo --krb5ccname=$KRB5CCNAME --krb5auth="$DOMAIN/$USERNAME"%"$PASSWORD" || failed=`expr $failed + 1`

testit "wbinfo --separator against $TARGET" $wbinfo --separator || failed=`expr $failed + 1`

if test "$TARGET" = "ad_member"; then
	testit "wbinfo --domain-info=$DOMAIN" $wbinfo --domain-info=$DOMAIN || failed=`expr $failed + 1`

	testit "wbinfo --dc-info=$DOMAIN" $wbinfo --dc-info=$DOMAIN || failed=`expr $failed + 1`
fi

testit_expect_failure "wbinfo -a against $TARGET with invalid password" $wbinfo -a "$DOMAIN/$USERNAME%InvalidPassword" && failed=`expr $failed + 1`

testit_expect_failure "wbinfo -K against $TARGET with invalid password" $wbinfo -K "$DOMAIN/$USERNAME%InvalidPassword" && failed=`expr $failed + 1`

rm -f $KRB5CCNAME_PATH

exit $failed
