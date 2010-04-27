#!/bin/sh
# install miscellaneous files

[ $# -eq 7 ] || {
    echo "Usage: installmisc.sh DESTDIR SRCDIR SETUPDIR BINDDIR SBINDDIR PYTHONDIR PYTHON"
    exit 1
}

DESTDIR="$1"
SRCDIR="$2"
SETUPDIR="$3"
BINDIR="$4"
SBINDIR="$5"
PYTHONDIR="$6"
PYTHON="$7"

cd $SRCDIR || exit 1

if $PYTHON -c "import sys; sys.exit('$PYTHONDIR' in sys.path)"; then
	PYTHON_PATH_NEEDS_FIXING=yes
	echo "sys.path in python scripts will be updated to include $PYTHONDIR"
else
	PYTHON_PATH_NEEDS_FIXING=no
fi

# fixup a python script to use the right path
fix_python_path() {
    f="$1"
    if egrep 'sys.path.insert.*bin/python' $f > /dev/null; then
        if [ "$PYTHON_PATH_NEEDS_FIXING" = "yes" ]; then
            # old systems don't have sed -i :-(
            sed "s|\(sys.path.insert.*\)bin/python\(.*\)$|\1$PYTHONDIR\2|g" < $f > $f.$$ || exit 1
        else
            # old systems don't have sed -i :-(
            sed "s|\(sys.path.insert.*\)bin/python\(.*\)$||g" < $f > $f.$$ || exit 1
        fi
        mv -f $f.$$ $f || exit 1
        chmod +x $f
    fi
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
for p in provision
do
	cp setup/$p $SBINDIR || exit 1
	chmod a+x $SBINDIR/$p
	fix_python_path $SBINDIR/$p || exit 1
done

echo "Installing sbin scripts from scripting/bin/*"
for p in upgradeprovision samba_dnsupdate samba_spnupdate
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
cp setup/named.conf $SETUPDIR || exit 1
cp setup/named.conf.update $SETUPDIR || exit 1
cp setup/provision.smb.conf.dc $SETUPDIR || exit 1
cp setup/provision.smb.conf.member $SETUPDIR || exit 1
cp setup/provision.smb.conf.standalone $SETUPDIR || exit 1
cp setup/dns_update_list $SETUPDIR || exit 1
cp setup/spn_update_list $SETUPDIR || exit 1

echo "Installing external python libraries"
mkdir -p $DESTDIR$PYTHONDIR || exit 1
MISSING="$($PYTHON scripting/python/samba_external/missing.py)"
for p in $MISSING
do
  package=`basename $p`
  echo "Installing missing python package $package"
  mkdir -p $DESTDIR$PYTHONDIR/samba/external/$package
  touch $DESTDIR$PYTHONDIR/samba/external/__init__.py
  cp -r ../lib/$p/* $DESTDIR$PYTHONDIR/samba/external/$package/ || exit 1
done


exit 0
