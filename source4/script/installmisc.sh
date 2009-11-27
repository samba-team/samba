#!/bin/sh
# install miscellaneous files

[ $# -eq 5 ] || {
    echo "Usage: installmisc.sh SRCDIR SETUPDIR BINDDIR SBINDDIR PYTHONDIR"
    exit 1
}

SRCDIR="$1"
SETUPDIR="$2"
BINDIR="$3"
SBINDIR="$4"
PYTHONDIR="$5"

cd $SRCDIR || exit 1

# fixup a python script to use the right path
fix_python_path() {
    f="$1"
    egrep 'sys.path.insert.*bin/python' $f > /dev/null && {
	# old systems don't have sed -i :-(
	sed "s|\(sys.path.insert.*\)bin/python\(.*\)$|\1$PYTHONDIR\2|g" < $f > $f.$$ || exit 1
	mv -f $f.$$ $f || exit 1
	chmod +x $f
    }
}

echo "Installing setup templates"
mkdir -p $SETUPDIR || exit 1
mkdir -p $SBINDIR || exit 1
mkdir -p $BINDIR || exit 1
mkdir -p $SETUPDIR/ad-schema || exit 1
mkdir -p $SETUPDIR/display-specifiers || exit1
cp setup/ad-schema/*.txt $SETUPDIR/ad-schema || exit 1
cp setup/display-specifiers/*.txt $SETUPDIR/display-specifiers || exit 1

echo "Installing sbin scripts from setup/*"
for p in domainlevel enableaccount newuser provision setexpiry setpassword pwsettings
do
	cp setup/$p $SBINDIR || exit 1
	chmod a+x $SBINDIR/$p
	fix_python_path $SBINDIR/$p || exit 1
done

echo "Installing sbin scripts from scripting/bin/*"
for p in upgradeprovision
do
	cp scripting/bin/$p $SBINDIR || exit 1
	chmod a+x $SBINDIR/$p
	fix_python_path $SBINDIR/$p || exit 1
done

echo "Installing remaining files in $SETUPDIR"
cp setup/schema-map-* $SETUPDIR || exit 1
cp setup/DB_CONFIG $SETUPDIR || exit 1
cp setup/*.inf $SETUPDIR || exit 1
cp setup/*.ldif $SETUPDIR || exit 1
cp setup/*.reg $SETUPDIR || exit 1
cp setup/*.zone $SETUPDIR || exit 1
cp setup/*.conf $SETUPDIR || exit 1
cp setup/*.php $SETUPDIR || exit 1
cp setup/*.txt $SETUPDIR || exit 1
cp setup/provision.smb.conf.dc $SETUPDIR || exit 1
cp setup/provision.smb.conf.member $SETUPDIR || exit 1
cp setup/provision.smb.conf.standalone $SETUPDIR || exit 1

exit 0
