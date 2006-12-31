#!/bin/sh

WEBAPPSDIR=$1
SRCDIR=$2

echo Installing web application files in $WEBAPPSDIR

cd $SRCDIR/../webapps/swat || exit 1
make build || exit 1

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
cd build
installdir `find . -type f -print`
cd ..

# install all .esp files (there are none in the webapp build dir)
installdir `find . -name '*.esp'`

# install .js and .esp files from the scripting dir
cd ..
installdir `find scripting -name '*.js'`
installdir `find scripting -name '*.esp'`

# install .css files from the style dir
installdir `find style -name '*.css'`

# install files from the images dir
installdir `find images -type f -print`

# install the login script, for authentication of static pages
installdir `find . -name 'login.esp'`

cat << EOF
======================================================================
The web application files have been installed. 
======================================================================
EOF

exit 0

