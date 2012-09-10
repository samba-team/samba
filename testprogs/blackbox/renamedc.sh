#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: renamedc.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

. `dirname $0`/subunit.sh

if [ ! -d $PREFIX/renamedc_test ]; then
	$PYTHON $BINDIR/samba-tool domain provision --host-name=bar --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/renamedc_test" --server-role="dc" --use-ntvfs
fi


testrenamedc() {
	$PYTHON $SRCDIR/source4/scripting/bin/renamedc \
		--oldname="BAR" \
		--newname="RAYMONBAR" \
		-s $PREFIX/renamedc_test/etc/smb.conf
}


testrenamedc2() {
	$PYTHON $SRCDIR/source4/scripting/bin/renamedc \
		--oldname="RAYMONBAR" \
		--newname="BAR" \
		-s $PREFIX/renamedc_test/etc/smb.conf
}

testit "renamedc" testrenamedc
testit "renamedc2" testrenamedc2

if [ $failed -eq 0 ]; then
	rm -rf $PREFIX/renamedc_test
fi

exit $failed
