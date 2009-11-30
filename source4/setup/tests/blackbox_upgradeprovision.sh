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

upgradeprovision() {
	$PYTHON ./setup/provision --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/upgradeprovision" --server-role="dc"
	$PYTHON ./scripting/bin/upgradeprovision -s "$PREFIX/upgradeprovision/etc/smb.conf"
}

upgradeprovision_full() {
	$PYTHON ./setup/provision --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/upgradeprovision_full" --server-role="dc"
	$PYTHON ./scripting/bin/upgradeprovision -s "$PREFIX/upgradeprovision_full/etc/smb.conf" --full
}

testit "upgradeprovision" upgradeprovision
testit "upgradeprovision_full" upgradeprovision_full

exit $failed
