#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_upgradeprovision.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

. `dirname $0`/subunit.sh

if [ ! -d $PREFIX/upgradeprovision_full ]; then
	$PYTHON $SRCDIR/source4/setup/provision --host-name=bar --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/upgradeprovision_full" --server-role="dc"
fi


testrenamedc() {
	$PYTHON $SRCDIR/source4/scripting/bin/renamedc \
		--oldname="BAR" \
		--newname="RAYMONBAR" \
		-s $PREFIX/upgradeprovision_full/etc/smb.conf
}


testrenamedc2() {
	$PYTHON $SRCDIR/source4/scripting/bin/renamedc \
		--oldname="RAYMONBAR" \
		--newname="BAR" \
		-s $PREFIX/upgradeprovision_full/etc/smb.conf
}

testit "renamedc" testrenamedc
testit "renamedc2" testrenamedc2

if [ $failed -eq 0 ]; then
	rm -rf $PREFIX/upgradeprovision_full
fi

exit $failed
