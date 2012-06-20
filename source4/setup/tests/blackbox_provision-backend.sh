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

testit "openldap-backend" $PYTHON $SRCDIR/source4/setup/provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend
testit "openldap-mmr-backend" $PYTHON $SRCDIR/source4/setup/provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-mmr-backend --ol-mmr-urls="ldap://s4dc1.test:9000,ldap://s4dc2.test:9000" --username=samba-admin --password=linux --adminpass=linux --ldapadminpass=linux
testit "fedora-ds-backend" $PYTHON $SRCDIR/source4/setup/provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend

reprovision() {
        $PYTHON $SRCDIR/source4/setup/provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend-reprovision
        $PYTHON $SRCDIR/source4/setup/provision --domain=FOO --realm=foo.example.com --ldap-backend-type=openldap --targetdir=$PREFIX/openldap-backend-reprovision
}

testit "reprovision-backend" reprovision

exit $failed
