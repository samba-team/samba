#!/bin/sh
# Blackbox tests for samba-tool ntacl get/set on member server
# Copyright (C) 2018 Björn Baumbach <bb@sernet.de>

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_net_ads_dns.sh PREFIX
EOF
exit 1;
fi

PREFIX=$1

failed=0

samba4bindir="$BINDIR"
samba_tool="$samba4bindir/samba-tool"

testfile="$PREFIX/ntacl_testfile"

# acl from samba_tool/ntacl.py tests
acl="O:DAG:DUD:P(A;OICI;0x001f01ff;;;DA)(A;OICI;0x001f01ff;;;EA)(A;OICIIO;0x001f01ff;;;CO)(A;OICI;0x001f01ff;;;DA)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001200a9;;;AU)(A;OICI;0x001200a9;;;ED)S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"

. `dirname $0`/subunit.sh

UID_WRAPPER_ROOT=1
export UID_WRAPPER_ROOT

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

testit "set_ntacl" test_set_acl "$testfile" "$acl" || failed=`expr $failed + 1`

testit "get_ntacl" test_get_acl "$testfile" "$acl" || failed=`expr $failed + 1`

rm -f "$testfile"

exit $failed
