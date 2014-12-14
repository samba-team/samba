#!/bin/sh
# Pull in a new snapshot of external projects that are included in 
# our source tree for users that don't have them installed on their system

# Third party directory
THIRD_PARTY_DIR="`dirname $0`/../third_party"
# Library directory where projects live that haven't been migrated to
# $THIRD_PARTY_DIR yet.
LIBDIR="`dirname $0`"
WORKDIR="`mktemp -d`"

echo "Updating testtools..."
git clone git://github.com/testing-cabal/testtools "$WORKDIR/testtools"
rm -rf "$WORKDIR/testtools/.git"
rsync -avz --delete "$WORKDIR/testtools/" "$LIBDIR/testtools/"

echo "Updating dnspython..."
git clone git://www.dnspython.org/dnspython.git "$WORKDIR/dnspython"
rm -rf "$WORKDIR/dnspython/.git"
rsync -avz --delete "$WORKDIR/dnspython/" "$LIBDIR/dnspython/"

echo "Updating pep8..."
git clone git://github.com/jcrocholl/pep8 "$WORKDIR/pep8"
rm -rf "$WORKDIR/pep8/.git"
rsync -avz --delete "$WORKDIR/pep8/" "$LIBDIR/pep8/"

echo "Updating zlib..."
git clone git://github.com/madler/zlib "$WORKDIR/zlib"
rm -rf "$WORKDIR/zlib/.git"
rsync --exclude=wscript -avz --delete "$WORKDIR/zlib/" "$THIRD_PARTY_DIR/zlib/"

echo "Updating extra..."
git clone git://github.com/testing-cabal/extras "$WORKDIR/extras"
rm -rf "$WORKDIR/extras/.git"
rsync -avz --delete "$WORKDIR/extras/" "$LIBDIR/extras/"

echo "Updating extra..."
git clone git://github.com/testing-cabal/extras "$WORKDIR/extras"
rm -rf "$WORKDIR/extras/.git"
rsync -avz --delete "$WORKDIR/extras/" "$LIBDIR/extras/"

echo "Updating mimeparse..."
svn co http://mimeparse.googlecode.com/svn/trunk/ "$WORKDIR/mimeparse"
rm -rf "$WORKDIR/mimeparse/.svn"
rsync -avz --delete "$WORKDIR/mimeparse/" "$LIBDIR/mimeparse/"

echo "Updating pyiso8601..."
hg clone https://bitbucket.org/micktwomey/pyiso8601 "$WORKDIR/pyiso8601"
rm -rf "$WORKDIR/pyiso8601/.hg"
rsync -avz --delete "$WORKDIR/pyiso8601/" "$THIRD_PARTY_DIR/pyiso8601/"

rm -rf "$WORKDIR"
