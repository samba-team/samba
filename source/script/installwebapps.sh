#!/bin/sh

WEBAPPSDIR=$1
SRCDIR=$2

echo Installing web application files in $WEBAPPSDIR

cd $SRCDIR/../webapps/swat || exit 1

# building the web application framework is now done by autogen.sh
#make build || exit 1

mkdir -p $WEBAPPSDIR || exit 1

installdir() {
    for f in $*; do
	dname=`dirname $f`
	echo "Installing $f in $dname"
	test -d $WEBAPPSDIR/$dname || mkdir -p $WEBAPPSDIR/$dname || exit 1
	cp $f $WEBAPPSDIR/$dname/ || exit 1
	chmod 0644 $WEBAPPSDIR/$f || exit 1
    done
}

# install our web application
cd build || exit 1
installdir `find . -type f -print`

# install files from the 'scripting', 'style' and 'images' directories
cd ../.. || exit 1
installdir `find scripting -name '*.js'`
installdir `find scripting -name '*.esp'`
installdir `find style -name '*.css'`
installdir `find images -name '*.png'`
installdir `find images -name '*.gif'`
installdir `find images -name '*.ico'`

# install the old installation scripts, since there's no replacement yet
installdir `find install -name '*.esp'`

# install top-level scripts
installdir index.esp login.esp logout.esp menu.js

cat << EOF
======================================================================
The web application files have been installed. 
======================================================================
EOF

exit 0

