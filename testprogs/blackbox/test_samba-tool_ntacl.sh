#!/bin/sh
# Blackbox tests for samba-tool ntacl get/set on member server
# Copyright (C) 2018 Björn Baumbach <bb@sernet.de>

if [ $# -ne 3 ]; then
	echo "Usage: test_samba-tool_ntacl.sh PREFIX DOMSID CONFIGURATION"
	exit 1
fi

PREFIX=$1
domain_sid=$2
CONFIGURATION=$3

failed=0

samba4bindir="$BINDIR"
samba_tool="$samba4bindir/samba-tool"

testfile="$PREFIX/ntacl_testfile"

# acl from samba_tool/ntacl.py tests
acl="O:DAG:DUD:P(A;OICI;FA;;;DA)(A;OICI;FA;;;EA)(A;OICIIO;FA;;;CO)(A;OICI;FA;;;DA)(A;OICI;FA;;;SY)(A;OICI;0x001200a9;;;AU)(A;OICI;0x001200a9;;;ED)S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
new_acl="O:S-1-5-21-2212615479-2695158682-2101375468-512G:S-1-5-21-2212615479-2695158682-2101375468-513D:P(A;OICI;FA;;;S-1-5-21-2212615479-2695158682-2101375468-512)(A;OICI;FA;;;S-1-5-21-2212615479-2695158682-2101375468-519)(A;OICIIO;FA;;;CO)(A;OICI;FA;;;S-1-5-21-2212615479-2695158682-2101375468-512)(A;OICI;FA;;;SY)(A;OICI;0x001200a9;;;AU)(A;OICI;0x001200a9;;;ED)S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
new_domain_sid="S-1-5-21-2212615479-2695158682-2101375468"

acl_without_padding=$(echo -n "$acl" | perl -p -e 's/0x00/0x/g')
new_acl_without_padding=$(echo -n "$new_acl" | perl -p -e 's/0x00/0x/g')

. $(dirname $0)/subunit.sh

test_get_acl()
{
	testfile="$1"
	exptextedacl="$2"

	retacl=$($PYTHON $samba_tool ntacl get "$testfile" --as-sddl) || return $?

	test "$retacl" = "$exptextedacl"
}

test_set_acl()
{
	testfile="$1"
	acl="$2"

	$PYTHON $samba_tool ntacl set "$acl" "$testfile"
}

test_get_acl_ntvfs()
{
	testfile="$1"
	exptextedacl="$2"

	retacl=$($PYTHON $samba_tool ntacl get "$testfile" --as-sddl --use-ntvfs --xattr-backend=tdb $CONFIGURATION) || return $?

	test "$retacl" = "$exptextedacl"
}

test_set_acl_ntvfs()
{
	testfile="$1"
	acl="$2"

	$PYTHON $samba_tool ntacl set "$acl" "$testfile" --use-ntvfs --xattr-backend=tdb $CONFIGURATION
}

test_changedomsid()
{
	testfile="$1"

	$PYTHON $samba_tool ntacl changedomsid \
		"$domain_sid" "$new_domain_sid" "$testfile" \
		--service=tmp \
		$CONFIGURATION

	retacl=$($PYTHON $samba_tool ntacl get \
		"$testfile" \
		--as-sddl \
		--service=tmp \
		$CONFIGURATION) || return $?

	test "$retacl" = "$new_acl_without_padding"
}

test_changedomsid_ntvfs()
{
	testfile="$1"

	$PYTHON $samba_tool ntacl changedomsid \
		"$domain_sid" "$new_domain_sid" "$testfile" \
		--use-ntvfs \
		--xattr-backend=tdb \
		$CONFIGURATION

	retacl=$($PYTHON $samba_tool ntacl get \
		"$testfile" \
		--as-sddl \
		--xattr-backend=tdb \
		--use-ntvfs \
		$CONFIGURATION) || return $?
	test "$retacl" = "$new_acl_without_padding"
}

# work around include error - s4-loadparm does not allow missing include files
#
# Unable to load file /home/bbaumba/src/git/samba/st/ad_member/lib/server.conf
#  File "bin/python/samba/netcmd/__init__.py", line 183, in _run
#    return self.run(*args, **kwargs)
#  File "bin/python/samba/netcmd/ntacl.py", line 175, in run
#    lp = sambaopts.get_loadparm()
#  File "bin/python/samba/getopt.py", line 92, in get_loadparm
#    self._lp.load(os.getenv("SMB_CONF_PATH"))
#    Processing section "[global]"
touch "$(dirname $SMB_CONF_PATH)/error_inject.conf"
touch "$(dirname $SMB_CONF_PATH)/delay_inject.conf"

touch "$testfile"

testit "set_ntacl" test_set_acl "$testfile" "$acl" || failed=$(expr $failed + 1)

testit "get_ntacl" test_get_acl "$testfile" "$acl_without_padding" || failed=$(expr $failed + 1)

testit "changedomsid" test_changedomsid "$testfile" || failed=$(expr $failed + 1)

testit "set_ntacl_ntvfs" test_set_acl_ntvfs "$testfile" "$acl" || failed=$(expr $failed + 1)
testit "get_ntacl_ntvfs" test_get_acl_ntvfs "$testfile" "$acl_without_padding" || \
    failed=$(expr $failed + 1)

testit "changedomsid_ntvfs" test_changedomsid_ntvfs "$testfile" || failed=$(expr $failed + 1)

rm -f "$testfile"

exit $failed
