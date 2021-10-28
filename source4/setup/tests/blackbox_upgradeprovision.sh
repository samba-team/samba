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

upgradeprovision_reference() {
  if [ -d $PREFIX/upgradeprovision_reference ]; then
    rm -fr $PREFIX/upgradeprovision_reference
  fi
	$PYTHON $BINDIR/samba-tool domain provision --host-name=bar --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/upgradeprovision_reference" --server-role="dc" --use-ntvfs --base-schema=2008_R2
}

upgradeprovision() {
  if [ -d $PREFIX/upgradeprovision ]; then
    rm -fr $PREFIX/upgradeprovision
  fi
	$PYTHON $BINDIR/samba-tool domain provision --host-name=bar --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/upgradeprovision" --server-role="dc" --use-ntvfs --base-schema=2008_R2
	$PYTHON $BINDIR/samba_upgradeprovision -s "$PREFIX/upgradeprovision/etc/smb.conf" --debugchange
}

upgradeprovision_full() {
  if [ -d $PREFIX/upgradeprovision_full ]; then
    rm -fr $PREFIX/upgradeprovision_full
  fi
	$PYTHON $BINDIR/samba-tool domain provision --host-name=bar --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/upgradeprovision_full" --server-role="dc" --use-ntvfs --base-schema=2008_R2
	$PYTHON $BINDIR/samba_upgradeprovision -s "$PREFIX/upgradeprovision_full/etc/smb.conf" --full --debugchange
}

# The ldapcmp runs here are to ensure that a 'null' run of
# upgradeprovision (because we did a provision with the same template)
# really doesn't change anything.

ldapcmp() {
        $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX/upgradeprovision/private/sam.ldb tdb://$PREFIX/upgradeprovision_reference/private/sam.ldb --two --skip-missing-dn --filter=servicePrincipalName
}

ldapcmp_full() {
        $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX/upgradeprovision_full/private/sam.ldb tdb://$PREFIX/upgradeprovision_reference/private/sam.ldb --two --skip-missing-dn --filter=servicePrincipalName
}

ldapcmp_sd() {
        $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX/upgradeprovision/private/sam.ldb tdb://$PREFIX/upgradeprovision_reference/private/sam.ldb --two --sd --skip-missing-dn --filter=servicePrincipalName
}

ldapcmp_full_sd() {
        $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX/upgradeprovision_full/private/sam.ldb tdb://$PREFIX/upgradeprovision_reference/private/sam.ldb --two --sd --skip-missing-dn --filter=servicePrincipalName
}

testit "upgradeprovision" upgradeprovision
testit "upgradeprovision_full" upgradeprovision_full
testit "upgradeprovision_reference" upgradeprovision_reference
testit "ldapcmp" ldapcmp
testit "ldapcmp_full" ldapcmp_full
testit "ldapcmp_sd" ldapcmp_sd
testit "ldapcmp_full_sd" ldapcmp_full_sd

if [ -d $PREFIX/upgradeprovision ]; then
  rm -fr $PREFIX/upgradeprovision
fi

if [ -d $PREFIX/upgradeprovision_full ]; then
  rm -fr $PREFIX/upgradeprovision_full
fi

if [ -d $PREFIX/upgradeprovision_reference ]; then
  rm -fr $PREFIX/upgradeprovision_reference
fi

exit $failed
