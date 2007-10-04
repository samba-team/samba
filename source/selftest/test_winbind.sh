#!/bin/sh
#

incdir=`dirname $0`
. $incdir/test_functions.sh

ENVNAME=$1
if test x"$ENVNAME" = x"";then
	ENVNAME="dc"
fi

WB_OPTS="${TORTURE_OPTIONS}"
WB_OPTS="${WB_OPTS} --option=\"torture:strict mode=yes\""
WB_OPTS="${WB_OPTS} --option=\"torture:timelimit=1\""
WB_OPTS="${WB_OPTS} --option=\"torture:winbindd separator=\\\\\""
WB_OPTS="${WB_OPTS} --option=\"torture:winbindd private pipe dir=\$WINBINDD_PRIV_PIPE_DIR\""
WB_OPTS="${WB_OPTS} --option=\"torture:winbindd netbios name=\$SERVER\""
WB_OPTS="${WB_OPTS} --option=\"torture:winbindd netbios domain=\$DOMAIN\""

STRUCT_TESTS=`$samba4bindir/smbtorture --list | grep "^WINBIND-STRUCT" | xargs`
for t in $STRUCT_TESTS; do
	plantest "$ENVNAME:$t" $ENVNAME $samba4bindir/smbtorture $WB_OPTS //_none_/_none_ $t
done

NDR_TESTS=`$samba4bindir/smbtorture --list | grep "^WINBIND-NDR" | xargs`
for t in $NDR_TESTS; do
	plantest "$ENVNAME:$t" $ENVNAME $samba4bindir/smbtorture $WB_OPTS //_none_/_none_ $t
done
