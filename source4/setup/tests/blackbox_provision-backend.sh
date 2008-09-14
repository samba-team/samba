#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_provision.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

. `dirname $0`/../../../testprogs/blackbox/subunit.sh

testit "openldap-backend" $PYTHON ./setup/provision-backend --domain=FOO --realm=foo.example.com --host-name=samba --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend
testit "openldap-mmr-backend" $PYTHON ./setup/provision-backend --domain=FOO --realm=foo.example.com --host-name=samba --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-mmr-backend --ol-mmr-urls='ldap://localdc1:9000,ldap://localdc2:9000,ldap://localdc3:9000'
testit "fedora-ds-backend" $PYTHON ./setup/provision-backend --domain=FOO --realm=foo.example.com --host-name=samba --ldap-backend-type=fedora-ds --targetdir=$PREFIX/fedora-ds-backend

reprovision() {
	$PYTHON ./setup/provision-backend --domain=FOO --realm=foo.example.com --host-name=samba --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend-reprovision
	$PYTHON ./setup/provision-backend --domain=FOO --realm=foo.example.com --host-name=samba --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend-reprovision
}

testit "reprovision-backend" reprovision

exit $failed
