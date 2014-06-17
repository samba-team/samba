#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: dbcheck.sh PREFIX RELEASE
EOF
exit 1;
fi

PREFIX_ABS="$1"
RELEASE="$2"
shift 2

. `dirname $0`/subunit.sh

release_dir=`dirname $0`/../../source4/selftest/provisions/$RELEASE

ldbmodify="ldbmodify"
if [ -x "$BINDIR/ldbmodify" ]; then
    ldbmodify="$BINDIR/ldbmodify"
fi

undump() {
       if test -x $BINDIR/tdbrestore;
       then
	`dirname $0`/../../source4/selftest/provisions/undump.sh $release_dir $PREFIX_ABS/$RELEASE $BINDIR/tdbrestore
       else
	`dirname $0`/../../source4/selftest/provisions/undump.sh $release_dir $PREFIX_ABS/$RELEASE
       fi
}

add_userparameters0() {
       if [ x$RELEASE = x"release-4-1-0rc3" ]; then
	   $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb <<EOF
dn: cn=localdc,cn=domain controllers,dc=release-4-1-0rc3,dc=samba,dc=corp
changetype: modify
replace: userParameters
userParameters:: IAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAC
 AAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAUAAQABoACAAB
 AEMAdAB4AEMAZgBnAFAAcgBlAHMAZQBuAHQANTUxZTBiYjAYAAgAAQBDAHQAeABDAGYAZw
 BGAGwAYQBnAHMAMQAwMGUwMDAxMBYACAABAEMAdAB4AEMAYQBsAGwAYgBhAGMAawAwMDAw
 MDAwMBIACAABAEMAdAB4AFMAaABhAGQAbwB3ADAxMDAwMDAwKAAIAAEAQwB0AHgATQBhAH
 gAQwBvAG4AbgBlAGMAdABpAG8AbgBUAGkAbQBlADAwMDAwMDAwLgAIAAEAQwB0AHgATQBh
 AHgARABpAHMAYwBvAG4AbgBlAGMAdABpAG8AbgBUAGkAbQBlADAwMDAwMDAwHAAIAAEAQw
 B0AHgATQBhAHgASQBkAGwAZQBUAGkAbQBlADAwMDAwMDAwIgAIAAEAQwB0AHgASwBlAHkA
 YgBvAGEAcgBkAEwAYQB5AG8AdQB0ADAwMDAwMDAwKgACAAEAQwB0AHgATQBpAG4ARQBuAG
 MAcgB5AHAAdABpAG8AbgBMAGUAdgBlAGwAMDAgAAIAAQBDAHQAeABXAG8AcgBrAEQAaQBy
 AGUAYwB0AG8AcgB5ADAwIAACAAEAQwB0AHgATgBXAEwAbwBnAG8AbgBTAGUAcgB2AGUAcg
 AwMBgAJAABAEMAdAB4AFcARgBIAG8AbQBlAEQAaQByADVjNWM3MzYxNzQ3NTcyNmU2NTVj
 NzAyZTYyNjk2NDZmNmUwMCIABgABAEMAdAB4AFcARgBIAG8AbQBlAEQAaQByAEQAcgBpAH
 YAZQA1MDNhMDAgADoAAQBDAHQAeABXAEYAUAByAG8AZgBpAGwAZQBQAGEAdABoADVjNWM3
 MzYxNzQ3NTcyNmU2NTVjNzA3MjZmNjY2OTZjNjU3NDczNjU1YzcwMmU2MjY5NjQ2ZjZlMD
 AiAAIAAQBDAHQAeABJAG4AaQB0AGkAYQBsAFAAcgBvAGcAcgBhAG0AMDAiAAIAAQBDAHQA
 eABDAGEAbABsAGIAYQBjAGsATgB1AG0AYgBlAHIAMDA=
-
EOF
       fi
}
add_userparameters1() {
       if [ x$RELEASE = x"release-4-1-0rc3" ]; then
	   $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb <<EOF
dn: cn=administrator,cn=users,dc=release-4-1-0rc3,dc=samba,dc=corp
changetype: modify
replace: userParameters
userParameters: IAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAC
 AAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAUAAQABoACAAB
 AEMAdAB4AEMAZgBnAFAAcgBlAHMAZQBuAHQANTUxZTBiYjAYAAgAAQBDAHQAeABDAGYAZw
 BGAGwAYQBnAHMAMQAwMGUwMDAxMBYACAABAEMAdAB4AEMAYQBsAGwAYgBhAGMAawAwMDAw
 MDAwMBIACAABAEMAdAB4AFMAaABhAGQAbwB3ADAxMDAwMDAwKAAIAAEAQwB0AHgATQBhAH
 gAQwBvAG4AbgBlAGMAdABpAG8AbgBUAGkAbQBlADAwMDAwMDAwLgAIAAEAQwB0AHgATQBh
 AHgARABpAHMAYwBvAG4AbgBlAGMAdABpAG8AbgBUAGkAbQBlADAwMDAwMDAwHAAIAAEAQw
 B0AHgATQBhAHgASQBkAGwAZQBUAGkAbQBlADAwMDAwMDAwIgAIAAEAQwB0AHgASwBlAHkA
 YgBvAGEAcgBkAEwAYQB5AG8AdQB0ADAwMDAwMDAwKgACAAEAQwB0AHgATQBpAG4ARQBuAG
 MAcgB5AHAAdABpAG8AbgBMAGUAdgBlAGwAMDAgAAIAAQBDAHQAeABXAG8AcgBrAEQAaQBy
 AGUAYwB0AG8AcgB5ADAwIAACAAEAQwB0AHgATgBXAEwAbwBnAG8AbgBTAGUAcgB2AGUAcg
 AwMBgAJAABAEMAdAB4AFcARgBIAG8AbQBlAEQAaQByADVjNWM3MzYxNzQ3NTcyNmU2NTVj
 NzAyZTYyNjk2NDZmNmUwMCIABgABAEMAdAB4AFcARgBIAG8AbQBlAEQAaQByAEQAcgBpAH
 YAZQA1MDNhMDAgADoAAQBDAHQAeABXAEYAUAByAG8AZgBpAGwAZQBQAGEAdABoADVjNWM3
 MzYxNzQ3NTcyNmU2NTVjNzA3MjZmNjY2OTZjNjU3NDczNjU1YzcwMmU2MjY5NjQ2ZjZlMD
 AiAAIAAQBDAHQAeABJAG4AaQB0AGkAYQBsAFAAcgBvAGcAcgBhAG0AMDAiAAIAAQBDAHQA
 eABDAGEAbABsAGIAYQBjAGsATgB1AG0AYgBlAHIAMDA=
-
EOF
       fi
}
add_userparameters2() {
       if [ x$RELEASE = x"release-4-1-0rc3" ]; then
	   $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb <<EOF
dn: cn=krbtgt,cn=users,dc=release-4-1-0rc3,dc=samba,dc=corp
changetype: modify
replace: userParameters
userParameters:: Q3R4Q2ZnUHJlc2VudCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI
 CAgUAsaCAFDdHhDZmdQcmVzZW5045S15pSx5oiw44GiIAIBQ3R4V0ZQcm9maWxlUGF0aOOAsBgCAU
 N0eFdGSG9tZURpcuOAsCICAUN0eFdGSG9tZURpckRyaXZl44CwEggBQ3R4U2hhZG9344Sw44Cw44C
 w44CwLggBQ3R4TWF4RGlzY29ubmVjdGlvblRpbWXjgaXjjLnjkLDjgLAoCAFDdHhNYXhDb25uZWN0
 aW9uVGltZeOAtOOct+aIseOAsBwIAUN0eE1heElkbGVUaW1l44Gj45yy46Sw44CwIAIBQ3R4V29ya
 0RpcmVjdG9yeeOAsBgIAUN0eENmZ0ZsYWdzMeOAsOOBpuOYsuOAuCICAUN0eEluaXRpYWxQcm9ncm
 Ft44Cw
-
EOF
       fi
}

add_userparameters3() {
       if [ x$RELEASE = x"release-4-1-0rc3" ]; then
	   $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb <<EOF
dn: cn=guest,cn=users,dc=release-4-1-0rc3,dc=samba,dc=corp
changetype: modify
replace: userParameters
userParameters:: QwAAAHQAAAB4AAAAQwAAAGYAAABnAAAAUAAAAHIAAABlAAAAcwAAAGUAAABuA
 AAAdAAAACAAAAAgAAAAIAAAACAAAAAgAAAAIAAAACAAAAAgAAAAIAAAACAAAAAgAAAAIAAAACAAAA
 AgAAAAIAAAACAAAAAgAAAAIAAAACAAAAAgAAAAIAAAACAAAAAgAAAAIAAAACAAAAAgAAAAIAAAACA
 AAAAgAAAAIAAAACAAAAAgAAAAIAAAACAAAAAgAAAAUAAAAAsAAAAaAAAACAAAAAEAAABDAAAAdAAA
 AHgAAABDAAAAZgAAAGcAAABQAAAAcgAAAGUAAABzAAAAZQAAAG4AAAB0AAAANQA1ADEAZQAwAGIAY
 gAwACAAAAACAAAAAQAAAEMAAAB0AAAAeAAAAFcAAABGAAAAUAAAAHIAAABvAAAAZgAAAGkAAABsAA
 AAZQAAAFAAAABhAAAAdAAAAGgAAAAwADAAGAAAAAIAAAABAAAAQwAAAHQAAAB4AAAAVwAAAEYAAAB
 IAAAAbwAAAG0AAABlAAAARAAAAGkAAAByAAAAMAAwACIAAAACAAAAAQAAAEMAAAB0AAAAeAAAAFcA
 AABGAAAASAAAAG8AAABtAAAAZQAAAEQAAABpAAAAcgAAAEQAAAByAAAAaQAAAHYAAABlAAAAMAAwA
 BIAAAAIAAAAAQAAAEMAAAB0AAAAeAAAAFMAAABoAAAAYQAAAGQAAABvAAAAdwAAADAAMQAwADAAMA
 AwADAAMAAuAAAACAAAAAEAAABDAAAAdAAAAHgAAABNAAAAYQAAAHgAAABEAAAAaQAAAHMAAABjAAA
 AbwAAAG4AAABuAAAAZQAAAGMAAAB0AAAAaQAAAG8AAABuAAAAVAAAAGkAAABtAAAAZQAAAGUAMAA5
 ADMAMAA0ADAAMAAoAAAACAAAAAEAAABDAAAAdAAAAHgAAABNAAAAYQAAAHgAAABDAAAAbwAAAG4AA
 ABuAAAAZQAAAGMAAAB0AAAAaQAAAG8AAABuAAAAVAAAAGkAAABtAAAAZQAAADQAMAA3ADcAMQBiAD
 AAMAAcAAAACAAAAAEAAABDAAAAdAAAAHgAAABNAAAAYQAAAHgAAABJAAAAZAAAAGwAAABlAAAAVAA
 AAGkAAABtAAAAZQAAAGMAMAAyADcAMAA5ADAAMAAgAAAAAgAAAAEAAABDAAAAdAAAAHgAAABXAAAA
 bwAAAHIAAABrAAAARAAAAGkAAAByAAAAZQAAAGMAAAB0AAAAbwAAAHIAAAB5AAAAMAAwABgAAAAIA
 AAAAQAAAEMAAAB0AAAAeAAAAEMAAABmAAAAZwAAAEYAAABsAAAAYQAAAGcAAABzAAAAMQAAADAAMA
 BmADAAMgA2ADgAMAAiAAAAAgAAAAEAAABDAAAAdAAAAHgAAABJAAAAbgAAAGkAAAB0AAAAaQAAAGE
 AAABsAAAAUAAAAHIAAABvAAAAZwAAAHIAAABhAAAAbQAAADAAMAA=
-
EOF
       fi
}

reindex() {
       $PYTHON $BINDIR/samba-tool dbcheck --reindex -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $@
}

# This should 'fail', because it returns the number of modified records
dbcheck() {
       $PYTHON $BINDIR/samba-tool dbcheck --cross-ncs --fix --yes -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $@
}
# But having fixed it all up, this should pass
dbcheck_clean() {
       $PYTHON $BINDIR/samba-tool dbcheck --cross-ncs -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $@
}

# This should 'fail', because it returns the number of modified records.  
# We don't need to run this against 4.1 releases
dbcheck_acl_reset() {
    if [ x$RELEASE = x"release-4-0-0" -o x$RELEASE = x"alpha13" ]; then
       $PYTHON $BINDIR/samba-tool dbcheck --reset-well-known-acls --cross-ncs --fix --yes -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $@
    else 
	return 1
    fi
}
# But having fixed it all up, this should pass.  
# We don't need to run this against 4.1.0rc3
dbcheck_acl_reset_clean() {
    if [ x$RELEASE != x"release-4-1-0rc3" ]; then
       $PYTHON $BINDIR/samba-tool dbcheck --reset-well-known-acls --cross-ncs -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $@
    fi
}

# This should 'fail', because it returns the number of modified records
dbcheck2() {
    if [ x$RELEASE = x"release-4-1-0rc3" ]; then
       $PYTHON $BINDIR/samba-tool dbcheck --cross-ncs --fix --yes -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $@
    else
	exit 1
    fi
}
# But having fixed it all up, this should pass
dbcheck_clean2() {
    if [ x$RELEASE = x"release-4-1-0rc3" ]; then
       $PYTHON $BINDIR/samba-tool dbcheck --cross-ncs -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $@
    fi
}

referenceprovision() {
    if [ x$RELEASE == x"release-4-0-0" ]; then
        $PYTHON $BINDIR/samba-tool domain provision --server-role="dc" --domain=SAMBA --host-name=ares --realm=${RELEASE}.samba.corp --targetdir=$PREFIX_ABS/${RELEASE}_reference --use-ntvfs --host-ip=127.0.0.1 --host-ip6=::1
    fi
}

ldapcmp() {
    if [ x$RELEASE == x"release-4-0-0" ]; then
         $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX_ABS/${RELEASE}_reference/private/sam.ldb tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --two --skip-missing-dn --filter=dnsRecord
    fi
}

ldapcmp_sd() {
    if [ x$RELEASE == x"release-4-0-0" ]; then
        $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX_ABS/${RELEASE}_reference/private/sam.ldb tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --two --sd --skip-missing-dn
    fi
}

if [ -d $release_dir ]; then
    testit $RELEASE undump
    testit "reindex" reindex
    testit_expect_failure "dbcheck" dbcheck
    testit "dbcheck_clean" dbcheck_clean
    testit_expect_failure "dbcheck_acl_reset" dbcheck_acl_reset
    testit "dbcheck_acl_reset_clean" dbcheck_acl_reset_clean
    testit "add_userparameters0" add_userparameters1
    testit "add_userparameters1" add_userparameters1
    testit "add_userparameters2" add_userparameters2
    testit "add_userparameters3" add_userparameters3
    testit_expect_failure "dbcheck2" dbcheck2
    testit "dbcheck_clean2" dbcheck_clean2
    testit "referenceprovision" referenceprovision
    testit "ldapcmp" ldapcmp
    testit "ldapcmp_sd" ldapcmp_sd
else
    subunit_start_test $RELEASE
    subunit_skip_test $RELEASE <<EOF
no test provision
EOF

    subunit_start_test "reindex"
    subunit_skip_test "reindex" <<EOF
no test provision
EOF
    subunit_start_test "dbcheck"
    subunit_skip_test "dbcheck" <<EOF
no test provision
EOF
    subunit_start_test "dbcheck_clean"
    subunit_skip_test "dbcheck_clean" <<EOF
no test provision
EOF
    subunit_start_test "dbcheck_acl_reset"
    subunit_skip_test "dbcheck_acl_reset" <<EOF
no test provision
EOF
    subunit_start_test "dbcheck_clean_acl_reset"
    subunit_skip_test "dbcheck_clean_acl_reset" <<EOF
no test provision
EOF
    subunit_start_test add_userparameters0
    subunit_skip_test add_userparameters0<<EOF
no test provision
EOF

    subunit_start_test add_userparameters1
    subunit_skip_test add_userparameters1<<EOF
no test provision
EOF

    subunit_start_test add_userparameters2
    subunit_skip_test add_userparameters2<<EOF
no test provision
EOF

    subunit_start_test add_userparameters3
    subunit_skip_test add_userparameters3<<EOF
no test provision
EOF

    subunit_start_test "dbcheck2"
    subunit_skip_test "dbcheck2" <<EOF
no test provision
EOF

    subunit_start_test "referenceprovision"
    subunit_skip_test "referenceprovision" <<EOF
no test provision
EOF
    subunit_start_test "ldapcmp"
    subunit_skip_test "ldapcmp" <<EOF
no test provision
EOF
    subunit_start_test "ldapcmp_sd"
    subunit_skip_test "ldapcmp_sd" <<EOF
no test provision
EOF
fi

if [ -d $PREFIX_ABS/${RELEASE} ]; then
  rm -fr $PREFIX_ABS/${RELEASE}
fi

if [ -d $PREFIX_ABS/${RELEASE}_reference ]; then
  rm -fr $PREFIX_ABS/${RELEASE}_reference
fi

exit $failed
