#!/bin/sh

if [ $# -lt 2 ]; then
cat <<EOF
Usage: blackbox_provision.sh PREFIX CONFIGURATION
EOF
exit 1;
fi

PREFIX="$1"
CONFIGURATION="$2"
shift 2

. `dirname $0`/../../../testprogs/blackbox/subunit.sh

testit "simple-default" $PYTHON ./setup/provision $CONFIGURATION --domain=FOO --realm=foo.example.com --targetdir=$PREFIX/simple-default
testit "simple-dc" $PYTHON ./setup/provision $CONFIGURATION --server-role="dc" --domain=FOO --realm=foo.example.com --domain-sid=S-1-5-21-4177067393-1453636373-93818738 --targetdir=$PREFIX/simple-dc
testit "simple-member" $PYTHON ./setup/provision $CONFIGURATION --server-role="member" --domain=FOO --realm=foo.example.com --targetdir=$PREFIX/simple-member
testit "simple-standalone" $PYTHON ./setup/provision $CONFIGURATION --server-role="standalone" --domain=FOO --realm=foo.example.com --targetdir=$PREFIX/simple-standalone
testit "blank-dc" $PYTHON ./setup/provision $CONFIGURATION --server-role="dc" --domain=FOO --realm=foo.example.com --domain-sid=S-1-5-21-4177067393-1453636373-93818738 --targetdir=$PREFIX/blank-dc --blank
testit "partitions-only-dc" $PYTHON ./setup/provision $CONFIGURATION --server-role="dc" --domain=FOO --realm=foo.example.com --domain-sid=S-1-5-21-4177067393-1453636373-93818738 --targetdir=$PREFIX/partitions-only-dc --partitions-only

reprovision() {
	$PYTHON ./setup/provision $CONFIGURATION --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/reprovision"
	$PYTHON ./setup/provision $CONFIGURATION --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/reprovision"
}

testit "reprovision" reprovision

exit $failed
