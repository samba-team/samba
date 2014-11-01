#!/bin/sh
# Blackbox test for wbinfo and rfc2307 mappings
if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_rfc2307_mapping.sh DOMAIN USERNAME PASSWORD SERVER UID_RFC2307TEST GID_RFC2307TEST
EOF
exit 1;
fi

DOMAIN=$1
USERNAME=$2
PASSWORD=$3
SERVER=$4
UID_RFC2307TEST=$5
GID_RFC2307TEST=$6
shift 6

failed=0
samba4bindir="$BINDIR"
wbinfo="$VALGRIND $samba4bindir/wbinfo"
samba_tool="$VALGRIND $samba4bindir/samba-tool"
if [ -f "$samba4bindir/ldbmodify" ]; then
	ldbmodify="$samba4bindir/ldbmodify"
else
	# Using system ldbmodify
	ldbmodify="ldbmodify"
fi

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


# Create new testing account
testit "user add" $samba_tool user create --given-name="rfc2307" --surname="Tester" --initial="UT" rfc2307_test_user testp@ssw0Rd $@

#test creation of six different groups
testit "group add" $samba_tool group add $CONFIG --group-scope='Domain' --group-type='Security' rfc2307_test_group $@

# Create new testing group

# Convert name to SID
testit "wbinfo -n against $TARGET" $wbinfo -n "$DOMAIN/rfc2307_test_user" || failed=`expr $failed + 1`
user_sid=`$wbinfo -n "$DOMAIN/rfc2307_test_user" | cut -d " " -f1`
echo "$DOMAIN/rfc2307_test_user resolved to $user_sid"

testit "wbinfo -s $user_sid against $TARGET" $wbinfo -s $user_sid || failed=`expr $failed + 1`
user_name=`$wbinfo -s $user_sid | cut -d " " -f1| tr a-z A-Z`
echo "$user_sid resolved to $user_name"

tested_name=`echo $DOMAIN/rfc2307_test_user | tr a-z A-Z`

# Now check that wbinfo works correctly (sid <=> name)
echo "test: wbinfo -s check for sane mapping"
if test x$user_name != x$tested_name; then
	echo "$user_name does not match $tested_name"
	echo "failure: wbinfo -s check for sane mapping"
	failed=`expr $failed + 1`
else
	echo "success: wbinfo -s check for sane mapping"
fi

testit "wbinfo -n on the returned name against $TARGET" $wbinfo -n $user_name || failed=`expr $failed + 1`
test_sid=`$wbinfo -n $tested_name | cut -d " " -f1`

echo "test: wbinfo -n check for sane mapping"
if test x$user_sid != x$test_sid; then
	echo "$user_sid does not match $test_sid"
	echo "failure: wbinfo -n check for sane mapping"
	failed=`expr $failed + 1`
else
	echo "success: wbinfo -n check for sane mapping"
fi

testit "wbinfo -n against $TARGET" $wbinfo -n "$DOMAIN/rfc2307_test_group" || failed=`expr $failed + 1`
group_sid=`$wbinfo -n "$DOMAIN/rfc2307_test_group" | cut -d " " -f1`
echo "$DOMAIN/rfc2307_test_group resolved to $group_sid"

# Then add a uidNumber to the group record using ldbmodify
cat > $PREFIX/tmpldbmodify <<EOF
dn: <SID=$user_sid>
changetype: modify
add: uidNumber
uidNumber: $UID_RFC2307TEST
EOF

testit "modify gidNumber on group" $VALGRIND $ldbmodify -H ldap://$SERVER $PREFIX/tmpldbmodify -U$DOMAIN/$USERNAME%$PASSWORD $@ || failed=`expr $failed + 1`

# Then add a gidNumber to the group record using ldbmodify
cat > $PREFIX/tmpldbmodify <<EOF
dn: <SID=$group_sid>
changetype: modify
add: gidNumber
gidNumber: $GID_RFC2307TEST
EOF

testit "modify gidNumber on group" $VALGRIND $ldbmodify -H ldap://$SERVER $PREFIX/tmpldbmodify -U$DOMAIN/$USERNAME%$PASSWORD $@ || failed=`expr $failed + 1`

rm -f $PREFIX/tmpldbmodify

# Now check we get a correct SID for the UID

testit "wbinfo -U against $TARGET" $wbinfo -U $UID_RFC2307TEST || failed=`expr $failed + 1`

echo "test: wbinfo -U check for sane mapping"
sid_for_user=`$wbinfo -U $UID_RFC2307TEST`
if test x"$sid_for_user" != x"$user_sid"; then
	echo "uid $UID_RFC2307TEST mapped to $sid_for_user, not $user_sid"
	echo "failure: wbinfo -U check for sane mapping"
	failed=`expr $failed + 1`
else
	echo "success: wbinfo -U check for sane mapping"
fi

testit "wbinfo -G against $TARGET" $wbinfo -G $GID_RFC2307TEST || failed=`expr $failed + 1`

echo "test: wbinfo -G check for sane mapping"
sid_for_group=`$wbinfo -G $GID_RFC2307TEST`
if test x$sid_for_group != "x$group_sid"; then
        echo "gid $GID_RFC2307TEST mapped to $sid_for_group, not $group_sid"
	echo "failure: wbinfo -G check for sane mapping"
	failed=`expr $failed + 1`
else
	echo "success: wbinfo -G check for sane mapping"
fi

# Now check we get the right UID from the SID
testit "wbinfo -S against $TARGET" $wbinfo -S "$user_sid" || failed=`expr $failed + 1`

echo "test: wbinfo -S check for sane mapping"
uid_for_user_sid=`$wbinfo -S $user_sid`
if test 0$uid_for_user_sid -ne $UID_RFC2307TEST; then
	echo "$user_sid mapped to $uid_for_sid, not $UID_RFC2307TEST"
	echo "failure: wbinfo -S check for sane mapping"
	failed=`expr $failed + 1`
else
	echo "success: wbinfo -S check for sane mapping"
fi

# Now check we get the right GID from the SID
testit "wbinfo -Y" $wbinfo -Y "$group_sid" || failed=`expr $failed + 1`

echo "test: wbinfo -Y check for sane mapping"
gid_for_user_sid=`$wbinfo -Y $group_sid`
if test 0$gid_for_user_sid -ne $GID_RFC2307TEST; then
	echo "$group_sid mapped to $gid_for_sid, not $GID_RFC2307TEST"
	echo "failure: wbinfo -Y check for sane mapping"
	failed=`expr $failed + 1`
else
	echo "success: wbinfo -Y check for sane mapping"
fi

testit "group delete" $samba_tool group delete rfc2307_test_group $@
testit "user delete" $samba_tool user delete rfc2307_test_user $@

exit $failed
