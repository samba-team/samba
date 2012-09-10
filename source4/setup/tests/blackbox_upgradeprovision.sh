#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_upgradeprovision.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

. `dirname $0`/../../../testprogs/blackbox/subunit.sh

[ ! -d $PREFIX ] && mkdir $PREFIX

upgradeprovision() {
  if [ -d $PREFIX/upgradeprovision ]; then
    rm -fr $PREFIX/upgradeprovision
  fi
	$PYTHON $BINDIR/samba-tool domain provision --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/upgradeprovision" --server-role="dc" --use-ntvfs
	$PYTHON $SRCDIR/source4/scripting/bin/upgradeprovision -s "$PREFIX/upgradeprovision/etc/smb.conf" --debugchange
}

upgradeprovision_full() {
  if [ -d $PREFIX/upgradeprovision_full ]; then
    rm -fr $PREFIX/upgradeprovision_full
  fi
	$PYTHON $BINDIR/samba-tool domain provision --host-name=bar --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/upgradeprovision_full" --server-role="dc" --use-ntvfs
	$PYTHON $SRCDIR/source4/scripting/bin/upgradeprovision -s "$PREFIX/upgradeprovision_full/etc/smb.conf" --full --debugchange
}

if [ -d $PREFIX/upgradeprovision ]; then
  rm -fr $PREFIX/upgradeprovision
fi

if [ -d $PREFIX/upgradeprovision_full ]; then
  rm -fr $PREFIX/upgradeprovision_full
fi

testit "upgradeprovision" upgradeprovision
testit "upgradeprovision_full" upgradeprovision_full

exit $failed
