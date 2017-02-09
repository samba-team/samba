#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_supported_features.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

DBPATH=$PREFIX/supported-features

mkdir -p $DBPATH

. `dirname $0`/../../../testprogs/blackbox/subunit.sh

ldbmodify="ldbmodify"
if [ -x "$BINDIR/ldbmodify" ]; then
    ldbmodify="$BINDIR/ldbmodify"
fi

ldbdel="ldbdel"
if [ -x "$BINDIR/ldbdel" ]; then
    ldbdel="$BINDIR/ldbdel"
fi

ldbsearch="ldbsearch"
if [ -x "$BINDIR/ldbsearch" ]; then
    ldbsearch="$BINDIR/ldbsearch"
fi

testit "provision" $PYTHON $BINDIR/samba-tool domain provision \
       --domain=FOO --realm=foo.example.com \
       --targetdir=$DBPATH --use-ntvfs

testit "add-compatible-feature" $ldbmodify \
       -H tdb://$DBPATH/private/sam.ldb <<EOF
dn: @SAMBA_DSDB
changetype: modify
add: compatibleFeatures
compatibleFeatures: non-existent-feature
-

EOF

# The non-existent feature is not compatible with this version, so it
# should not be listed in compatibleFeatures even though we tried to
# put it there.

ldb_search_fail() {
    $ldbsearch -H tdb://$DBPATH/private/sam.ldb \
               -s base -b "$1" "$2" \
        |   grep -q "$3"
}


testit_expect_failure "find-compatible-feature" \
                      ldb_search_fail '@SAMBA_DSDB' 'compatibleFeatures' non-existent-feature


# just make sure the thing we're using is normally findable
testit "find-test-feature" \
       $ldbsearch -H tdb://$DBPATH/private/sam.ldb \
       -b 'CN=LostAndFound,DC=foo,DC=example,DC=com'


testit "add-required-feature" $ldbmodify \
       -H tdb://$DBPATH/private/sam.ldb <<EOF
dn: @SAMBA_DSDB
changetype: modify
add: requiredFeatures
requiredFeatures: futuristic-feature
-

EOF

# The futuristic-feature is not implemented in this version, but it is
# required by this database. A search for anything should fail.

testit_expect_failure "find-required-feature" \
                      $ldbsearch -H tdb://$DBPATH/private/sam.ldb \
                      -b 'CN=LostAndFound,DC=foo,DC=example,DC=com'

rm -rf $DBPATH

exit $failed
