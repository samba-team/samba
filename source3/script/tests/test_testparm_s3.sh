#!/bin/sh

# Tests for lp_load() via testparm.
#
# The main purpose (for now) is to test all the special handlers
# and the macro expansions.

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_net_registry_roundtrip.sh LOCAL_PATH
EOF
exit 1;
fi

LOCAL_PATH="$1"

TEMP_CONFFILE=${LOCAL_PATH}/smb.conf.tmp
TESTPARM="$VALGRIND ${TESTPARM:-$BINDIR/testparm} --suppress-prompt --skip-logic-checks"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

test_include_expand_macro()
{
	MACRO=$1
	rm -f ${TEMP_CONFFILE}
	cat >${TEMP_CONFFILE}<<EOF
[global]
	include = ${TEMP_CONFFILE}.%${MACRO}
EOF
	${TESTPARM} ${TEMP_CONFFILE}
}

test_one_global_option()
{
	OPTION="$@"
	rm -f ${TEMP_CONFFILE}
	cat > ${TEMP_CONFFILE}<<EOF
[global]
	${OPTION}
EOF
	${TESTPARM} ${TEMP_CONFFILE}
}

test_copy()
{
	rm -f ${TEMP_CONFFILE}
	cat > ${TEMP_CONFFILE}<<EOF
[share1]
	path = /tmp
	read only = no

[share2]
	copy = share1
EOF
	${TESTPARM} ${TEMP_CONFFILE}
}

test_testparm_deprecated()
{
    name=$1
    old_SAMBA_DEPRECATED_SUPPRESS=$SAMBA_DEPRECATED_SUPPRESS
    SAMBA_DEPRECATED_SUPPRESS=
    export SAMBA_DEPRECATED_SUPPRESS
    testit_grep $name 'WARNING: The "lsaovernetlogon" option is deprecated' $VALGRIND ${TESTPARM} ${TEMP_CONFFILE} --option='lsaovernetlogon=true'
    SAMBA_DEPRECATED_SUPPRESS=$old_SAMBA_DEPRECATED_SUPPRESS
    export SAMBA_DEPRECATED_SUPPRESS
}

test_testparm_deprecated_suppress()
{
    name=$1
    subunit_start_test "$name"
    output=$(SAMBA_DEPRECATED_SUPPRESS=1 $VALGRIND ${TESTPARM} ${TEMP_CONFFILE} --option='lsa over netlogon = true' 2>&1)
    status=$?
    if [ "$status" = "0" ]; then
       echo "$output" | grep --quiet 'WARNING: The "lsa over netlogon " option is deprecated'
       status=$?
       if [ "$status" = "1" ]; then
           subunit_pass_test "$name"
       else
           echo $output | subunit_fail_test "$name"
       fi
    else
       echo $output | subunit_fail_test "$name"
    fi
}

testit "name resolve order = lmhosts wins host bcast"\
	test_one_global_option "name resolve order = lmhosts wins host bcast" || \
	failed=`expr ${failed} + 1`

testit_expect_failure "name resolve order = bad wins host bcast"\
	test_one_global_option "name resolve order = bad wins host bcast" || \
	failed=`expr ${failed} + 1`

testit_expect_failure "name resolve order = lmhosts bad host bcast"\
	test_one_global_option "name resolve order = lmhosts bad host bcast" || \
	failed=`expr ${failed} + 1`

testit_expect_failure "name resolve order = lmhosts wins bad bcast"\
	test_one_global_option "name resolve order = lmhosts wins bad bcast" || \
	failed=`expr ${failed} + 1`

testit_expect_failure "name resolve order = lmhosts wins host bad"\
	test_one_global_option "name resolve order = lmhosts wins host bad" || \
	failed=`expr ${failed} + 1`

testit "netbios name" \
	test_one_global_option "netbios name = funky" || \
	failed=`expr ${failed} + 1`

testit "netbios aliases" \
	test_one_global_option "netbios aliases = funky1 funky2 funky3" || \
	failed=`expr ${failed} + 1`

testit "netbios scope" \
	test_one_global_option "netbios scope = abc" || \
	failed=`expr ${failed} + 1`

testit "workgroup" \
	test_one_global_option "workgroup = samba" || \
	failed=`expr ${failed} + 1`

testit "display charset" \
	test_one_global_option "display charset = UTF8" || \
	failed=`expr ${failed} + 1`

testit "ldap debug level" \
	test_one_global_option "ldap debug level = 7" || \
	failed=`expr ${failed} + 1`

for LETTER in U G D I i L N M R T a d h m v w V ; do
testit "include with %${LETTER} macro expansion" \
	test_include_expand_macro "${LETTER}" || \
	failed=`expr ${failed} + 1`
done

testit "copy" \
	test_copy || \
	failed=`expr ${failed} + 1`

test_testparm_deprecated "test_deprecated_warning_printed"
test_testparm_deprecated_suppress "test_deprecated_warning_suppressed"

rm -f ${TEMP_CONFFILE}

testok $0 ${failed}

