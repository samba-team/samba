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

testit() {
	name="$1"
	shift
	cmdline="$*"
	echo "test: $name"
	$cmdline
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
		failed=`expr $failed + 1`
	fi
	return $status
}

testit "simple" $PYTHON ./setup/provision $CONFIGURATION --domain=FOO --realm=foo.example.com --targetdir=$PREFIX/simple

reprovision() {
	$PYTHON ./setup/provision $CONFIGURATION --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/reprovision"
	$PYTHON ./setup/provision $CONFIGURATION --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/reprovision"
}

testit "reprovision" reprovision

exit $failed
