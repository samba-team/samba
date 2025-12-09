#!/bin/sh

# Tests for lp_load() via testparm.
#
# The main purpose (for now) is to test all the special handlers
# and the macro expansions.

if [ $# -lt 1 ]; then
	cat <<EOF
Usage: test_testparm_s3.sh LOCAL_PATH
EOF
	exit 1
fi

LOCAL_PATH="$1"

TEMP_CONFFILE=${LOCAL_PATH}/smb.conf.tmp
TESTPARM="$VALGRIND ${TESTPARM:-$BINDIR/testparm} --suppress-prompt --skip-logic-checks"
TESTPARM_LOGIC="${BINDIR}/testparm --suppress-prompt"

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

test_include_expand_macro()
{
	MACRO=$1
	rm -f ${TEMP_CONFFILE}
	cat >${TEMP_CONFFILE} <<EOF
[global]
	include = ${TEMP_CONFFILE}.%${MACRO}
EOF
	${TESTPARM} ${TEMP_CONFFILE}
}

test_one_global_option()
{
	OPTION="$@"
	rm -f ${TEMP_CONFFILE}
	cat >${TEMP_CONFFILE} <<EOF
[global]
	${OPTION}
EOF
	${TESTPARM} ${TEMP_CONFFILE}
}

test_one_global_option_logic()
{
	OPTION="$@"
	rm -f ${TEMP_CONFFILE}
	cat >${TEMP_CONFFILE} <<EOF
[global]
	state directory = /tmp
	cache directory = /tmp
	${OPTION}
EOF
	${TESTPARM_LOGIC} ${TEMP_CONFFILE}
}

test_copy()
{
	rm -f ${TEMP_CONFFILE}
	cat >${TEMP_CONFFILE} <<EOF
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

testit "name resolve order = lmhosts wins host bcast" \
	test_one_global_option "name resolve order = lmhosts wins host bcast" ||
	failed=$(expr ${failed} + 1)

testit_expect_failure "name resolve order = bad wins host bcast" \
	test_one_global_option "name resolve order = bad wins host bcast" ||
	failed=$(expr ${failed} + 1)

testit_expect_failure "name resolve order = lmhosts bad host bcast" \
	test_one_global_option "name resolve order = lmhosts bad host bcast" ||
	failed=$(expr ${failed} + 1)

testit_expect_failure "name resolve order = lmhosts wins bad bcast" \
	test_one_global_option "name resolve order = lmhosts wins bad bcast" ||
	failed=$(expr ${failed} + 1)

testit_expect_failure "name resolve order = lmhosts wins host bad" \
	test_one_global_option "name resolve order = lmhosts wins host bad" ||
	failed=$(expr ${failed} + 1)

testit "netbios name" \
	test_one_global_option "netbios name = funky" ||
	failed=$(expr ${failed} + 1)

testit "netbios aliases" \
	test_one_global_option "netbios aliases = funky1 funky2 funky3" ||
	failed=$(expr ${failed} + 1)

testit "netbios scope" \
	test_one_global_option "netbios scope = abc" ||
	failed=$(expr ${failed} + 1)

testit "workgroup" \
	test_one_global_option "workgroup = samba" ||
	failed=$(expr ${failed} + 1)

testit "display charset" \
	test_one_global_option "display charset = UTF8" ||
	failed=$(expr ${failed} + 1)

testit "ldap debug level" \
	test_one_global_option "ldap debug level = 7" ||
	failed=$(expr ${failed} + 1)

for LETTER in U G D I i L N M R T a d h m v w V; do
	testit "include with %${LETTER} macro expansion" \
		test_include_expand_macro "${LETTER}" ||
		failed=$(expr ${failed} + 1)
done

testit "copy" \
	test_copy ||
	failed=$(expr ${failed} + 1)

test_testparm_deprecated "test_deprecated_warning_printed"
test_testparm_deprecated_suppress "test_deprecated_warning_suppressed"

testit "sync machine password to keytab 0" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab0:account_name:machine_password\"" ||
	failed=$(expr ${failed} + 1)
testit "sync machine password to keytab 1" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab1:account_name:sync_etypes:sync_kvno:machine_password\"" ||
	failed=$(expr ${failed} + 1)
testit "sync machine password to keytab 2" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab2:sync_spns:machine_password\"" ||
	failed=$(expr ${failed} + 1)
testit "sync machine password to keytab 3" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab3:sync_spns:sync_kvno:machine_password\"" ||
	failed=$(expr ${failed} + 1)
testit "sync machine password to keytab 4" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab4:spn_prefixes=imap,smtp:machine_password\"" ||
	failed=$(expr ${failed} + 1)
testit "sync machine password to keytab 5" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab5:spn_prefixes=imap,smtp:netbios_aliases:additional_dns_hostnames:sync_kvno:machine_password\"" ||
	failed=$(expr ${failed} + 1)
testit "sync machine password to keytab 6" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab6:spns=wurst/brot@REALM:machine_password\"" ||
	failed=$(expr ${failed} + 1)
testit "sync machine password to keytab 7" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab7:spns=wurst/brot@REALM,wurst2/brot@REALM:sync_kvno:machine_password\"" ||
	failed=$(expr ${failed} + 1)
testit "sync machine password to keytab 8" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab8:sync_account_name:sync_upn:sync_spns:spn_prefixes=host,cifs,http:spns=wurst/brot@REALM:sync_kvno:machine_password\"" ||
	failed=$(expr ${failed} + 1)
testit "sync machine password to keytab 9" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab9:machine_password\"" ||
	failed=$(expr ${failed} + 1)
testit_expect_failure "sync machine password to keytab 10" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab10\"" ||
	failed=$(expr ${failed} + 1)
testit_expect_failure "sync machine password to keytab 11" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab11:\"" ||
	failed=$(expr ${failed} + 1)
testit_expect_failure "sync machine password to keytab 12" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab12:foo\"" ||
	failed=$(expr ${failed} + 1)
testit_expect_failure "sync machine password to keytab 13" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab13:spns\"" ||
	failed=$(expr ${failed} + 1)
testit_expect_failure "sync machine password to keytab 14" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab14:spns=\"" ||
	failed=$(expr ${failed} + 1)
testit_expect_failure "sync machine password to keytab 15" \
	test_one_global_option_logic "sync machine password to keytab = \"/path/to/keytab15:machine_password=\"" ||
	failed=$(expr ${failed} + 1)

rm -f ${TEMP_CONFFILE}

testok $0 ${failed}
