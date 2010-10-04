#!/bin/sh

# this runs the file serving tests that are expected to pass with samba3

if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_posix_s3.sh UNC USERNAME PASSWORD <first> <smbtorture args>
EOF
exit 1;
fi

unc="$1"
username="$2"
password="$3"
start="$4"
shift 4
ADDARGS="$*"

test x"$TEST_FUNCTIONS_SH" != x"INCLUDED" && {
incdir=`dirname $0`
. $incdir/test_functions.sh
}

base="base.attr base.charset base.chkpath base.defer_open base.delaywrite base.delete"
base="$base base.deny1 base.deny2 base.deny3 base.denydos base.dir1 base.dir2"
base="$base base.disconnect base.fdpass base.lock"
base="$base base.mangle base.negnowait base.ntdeny1"
base="$base base.ntdeny2 base.open base.openattr base.properties base.rename base.rw1"
base="$base base.secleak base.tcon base.tcondev base.trans2 base.unlink base.vuid"
base="$base base.xcopy base.samba3error"

raw="raw.acls raw.chkpath raw.close raw.composite raw.context raw.eas"
raw="$raw raw.ioctl raw.lock raw.mkdir raw.mux raw.notify raw.open raw.oplock"
raw="$raw raw.qfileinfo raw.qfsinfo raw.read raw.rename raw.search raw.seek"
raw="$raw raw.sfileinfo.base raw.sfileinfo.bug raw.streams raw.unlink raw.write"
raw="$raw raw.samba3hide raw.samba3badpath raw.sfileinfo.rename"
raw="$raw raw.samba3caseinsensitive raw.samba3posixtimedlock"
raw="$raw raw.samba3rootdirfid raw.sfileinfo.end.of.file"

smb2="smb2.lock smb2.read smb2.compound smb2.connect smb2.scan smb2.scanfind"
smb2="$smb2 smb2.bench.oplock"

rpc="rpc.authcontext rpc.samba3.bind rpc.samba3.srvsvc rpc.samba3.sharesec"
rpc="$rpc rpc.samba3.spoolss rpc.samba3.wkssvc rpc.samba3.winreg"
rpc="$rpc rpc.samba3.getaliasmembership.0"
rpc="$rpc rpc.samba3.netlogon rpc.samba3.sessionkey rpc.samba3.getusername"
rpc="$rpc rpc.svcctl rpc.ntsvcs rpc.winreg rpc.eventlog"
rpc="$rpc rpc.spoolss.printserver rpc.spoolss.win rpc.spoolss.notify rpc.spoolss.printer"
rpc="$rpc rpc.spoolss.driver"
rpc="$rpc rpc.lsa.getuser rpc.lsa.lookupsids rpc.lsa.lookupnames"
rpc="$rpc rpc.lsa.privileges "
rpc="$rpc rpc.samr rpc.samr.users rpc.samr.users.privileges rpc.samr.passwords"
rpc="$rpc rpc.samr.passwords.pwdlastset rpc.samr.large.dc rpc.samr.machine.auth"
rpc="$rpc rpc.netlogon.s3 rpc.netlogon.admin"
rpc="$rpc rpc.schannel rpc.schannel2 rpc.bench.schannel1 rpc.join rpc.bind rpc.epmapper"

local="local.nss.wrapper local.ndr"

winbind="winbind.struct winbind.wbclient"

rap="rap.basic rap.rpc rap.printing rap.sam"

# note: to enable the unix-whoami test, we need to change the default share
# config to allow guest access. i'm not sure whether this would break other
# tests, so leaving it alone for now -- jpeach
unix="unix.info2"

tests="$base $raw $smb2 $rpc $unix $local $winbind $rap"

if test "x$POSIX_SUBTESTS" != "x" ; then
	tests="$POSIX_SUBTESTS"
fi

skipped="base.charset base.tcondev"
skipped="$skipped raw.acls raw.composite raw.context"
skipped="$skipped raw.ioctl"
skipped="$skipped raw.qfileinfo raw.qfsinfo"
skipped="$skipped raw.sfileinfo.base"

echo "WARNING: Skipping tests $skipped"

ADDARGS="$ADDARGS --option=torture:sharedelay=100000"
#ADDARGS="$ADDARGS --option=torture:writetimeupdatedelay=500000"

failed=0
for t in $tests; do
    if [ ! -z "$start" -a "$start" != $t ]; then
	continue;
    fi
    skip=0
    for s in $skipped; do
    	if [ x"$s" = x"$t" ]; then
    	    skip=1;
	    break;
	fi
    done
    if [ $skip = 1 ]; then
    	continue;
    fi
    start=""
    name="$t"
    if [ "$t" = "base.delaywrite" ]; then
	    testit "$name" $VALGRIND $SMBTORTURE4 $TORTURE4_OPTIONS --maximum-runtime=900 $ADDARGS $unc -U"$username"%"$password" $t || failed=`expr $failed + 1`
    else
	    testit "$name" $VALGRIND $SMBTORTURE4 $TORTURE4_OPTIONS $ADDARGS $unc -U"$username"%"$password" $t || failed=`expr $failed + 1`
    fi
    if [ "$t" = "raw.chkpath" ]; then
	    echo "Testing with case sensitive"
	    testit "$name" $VALGRIND $SMBTORTURE4 $TORTURE4_OPTIONS $ADDARGS "$unc"case -U"$username"%"$password" $t || failed=`expr $failed + 1`
    fi
done

testok $0 $failed
