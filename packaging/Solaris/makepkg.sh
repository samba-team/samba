#!/bin/sh
#
# Copyright (C) Shirish A Kalele 2000
# Copyright (C) Gerald Carter    2004
#
# script for build solaris Samba package
#

INSTALL_BASE=/opt/samba

SBINPROGS="smbd nmbd winbindd swat"
BINPROGS="findsmb nmblookup pdbedit rpcclient smbclient smbcquotas smbspool smbtar tdbbackup testparm wbinfo net ntlm_auth profiles smbcacls smbcontrol smbpasswd smbstatus smbtree tdbdump testprns"
MSGFILES="de.msg en.msg fr.msg it.msg ja.msg nl.msg pl.msg tr.msg"
VFSLIBS="audit.so default_quota.so extd_audit.so full_audit.so readonly.so shadow_copy.so cap.so expand_msdfs.so fake_perms.so netatalk.so recycle.so"
DATFILES="lowcase.dat upcase.dat valid.dat"
CHARSETLIBS="CP437.so CP850.so"

add_dynamic_entries() 
{
	# Add the binaries, docs and SWAT files
	cd $TMPINSTALLDIR/$INSTALL_BASE

	echo "#\n# Server Binaries \n#"	
 	for file in $SBINPROGS; do
		echo f none sbin/$file 0755 root other
	done

	echo "#\n# User Binaries \n#"
 	for file in $BINPROGS; do
		echo f none bin/$file 0755 root other
	done
	
	echo "#\n# Libraries\n#"
 	for file in $MSGFILES; do
		echo f none lib/$file 0644 root other
	done
 	for file in $DATFILES; do
		echo f none lib/$file 0644 root other
	done
 	for file in $VFSLIBS; do
		echo f none lib/vfs/$file 0755 root other
	done
 	for file in $CHARSETLIBS; do
		echo f none lib/charset/$file 0755 root other
	done
	
	echo "#\n# libsmbclient\n#"
	echo f none lib/libsmbclient.so 0755 root other
	echo f none include/libsmbclient.h 0644 root other

	echo "#\n# smbwrapper\n#"
	echo f none lib/smbwrapper.so 0755 root other
	echo f none bin/smbsh 0755 root other

	echo "#\n# nss_winbind.so\n#"
	echo f none /lib/nss_winbind.so.1=lib/nss_winbind.so.1 0755 root other
	# echo s none /lib/nss_winbind.so.1=/usr/lib/nss_winbind.so.1 0755 root other
	if [ -f lib/pam_winbind.so ]; then
		echo f none /usr/lib/security/pam_winbind.so=lib/pam_winbind.so 0755 root other
	fi

	echo "#\n# man pages \n#"

	# Create directories for man page sections if nonexistent
	cd man
	for i in 1 2 3 4 5 6 7 8 9; do
		manpages=`ls man$i 2>/dev/null`
		if [ $? -eq 0 ]; then
			echo d none man/man${i} ? ? ?
			for manpage in $manpages; do
				echo f none man/man${i}/${manpage} 0644 root other
			done
		fi
	done
	cd ..

	echo "#\n# SWAT \n#"
	list=`find swat -type d | grep -v "/.svn$"`
	for dir in $list; do
		if [ -d $dir ]; then
			echo d none $dir 0755 root other
		fi
	done

	list=`find swat -type f | grep -v /.svn/`
	for file in $list; do
		if [ -f $file ]; then
			echo f none $file 0644 root other
		fi
	done

	# Create entries for docs for the beginner
	echo 's none docs/using_samba=$BASEDIR/swat/using_samba'
	for file in docs/*pdf; do
		echo f none $file 0644 root other
	done
}

#####################################################################
## BEGIN MAIN 
#####################################################################

TMPINSTALLDIR=/export/build

# Try to guess the distribution base..
CURR_DIR=`pwd`
DISTR_BASE=`echo $CURR_DIR | sed 's|\(.*\)/packaging.*|\1|'`
echo "Assuming Samba distribution is rooted at $DISTR_BASE.."

##
## first build the source
##

cd $DISTR_BASE/source

if [ "x$1" != "xnobuild" ]; then
	./configure --prefix=$INSTALL_DIR \
		--with-acl-support \
		--with-included-popt \
		--localstatedir=/var/lib/samba \
		--with-piddir=/var/run \
		--with-logfilebase=/var/log/samba \
		--with-privatedir=/etc/samba/private \
		--with-configdir=/etc/samba \
	&& make

	if [ $? -ne 0 ]; then
		echo "Build failed!  Exiting...."
		exit 1
	fi
fi
	
make DESTDIR=$TMPINSTALLDIR install

## clear out *.old
( cd $TMPINSTALLDIR; du -a | grep \.old$ | awk '{print "rm -rf "$2}' | sh )

 
##
## Now get the install locations
##
SBINDIR=`bin/smbd -b | grep SBINDIR | awk '{print $2}'`
BINDIR=`bin/smbd -b | grep BINDIR | grep -v SBINDIR |  awk '{print $2}'`
SWATDIR=`bin/smbd -b | grep SWATDIR | awk '{print $2}'`
CONFIGFILE=`bin/smbd -b | grep CONFIGFILE | awk '{print $2}'`
CONFIGDIR=`dirname $CONFIGFILE`
LOGFILEBASE=`bin/smbd -b | grep LOGFILEBASE | awk '{print $2}'`
LIBDIR=`bin/smbd -b | grep LIBDIR | awk '{print $2}'`
PIDDIR=`bin/smbd -b | grep PIDDIR | awk '{print $2}'`
PRIVATE_DIR=`bin/smbd -b | grep PRIVATE_DIR | awk '{print $2}'`
DOCDIR=$INSTALL_BASE/docs

## 
## copy some misc files that are ont done as part of 'make install'
##
cp -fp nsswitch/libnss_winbind.so $TMPINSTALLDIR/$LIBDIR/nss_winbind.so.1
if [ -f nsswitch/pam_winbind.so ]; then
	cp -fp nsswitch/pam_winbind.so $TMPINSTALLDIR/$LIBDIR/pam_winbind.so
fi

cp -p bin/smbwrapper.so $TMPINSTALLDIR/$INSTALL_BASE/lib
cp -p bin/smbsh $TMPINSTALLDIR/$INSTALL_BASE/bin

mkdir -p $TMPINSTALLDIR/$INSTALL_BASE/docs
cp -p ../docs/*pdf $TMPINSTALLDIR/$INSTALL_BASE/docs


cd $DISTR_BASE/packaging/Solaris

##
## Main driver 
##

# Setup version from smbd -V

VERSION=`$TMPINSTALLDIR/$SBINDIR/smbd -V | awk '{print $2}'`
sed -e "s|__VERSION__|$VERSION|" -e "s|__ARCH__|`uname -p`|" -e "s|__BASEDIR__|$INSTALL_BASE|g" pkginfo.master > pkginfo

sed -e "s|__BASEDIR__|$INSTALL_BASE|g" inetd.conf.master   > inetd.conf
sed -e "s|__BASEDIR__|$INSTALL_BASE|g" samba.init.master > samba.init

##
## copy over some scripts need for packagaing
##
mkdir -p $TMPINSTALLDIR/$INSTALL_BASE/scripts
for i in inetd.conf samba.init smb.conf.default services; do
	cp -fp $i $TMPINSTALLDIR/$INSTALL_BASE/scripts
done

##
## Start building the prototype file
##
echo "CONFIGDIR=$CONFIGDIR" >> pkginfo
echo "LOGFILEBASE=$LOGFILEBASE" >> pkginfo
echo "PIDDIR=$PIDDIR" >> pkginfo
echo "PRIVATE_DIR=$PRIVATE_DIR" >> pkginfo

cp prototype.master prototype

# Add the dynamic part to the prototype file
(add_dynamic_entries >> prototype)

##
## copy packaging files 
##
for i in prototype pkginfo copyright preremove postinstall request i.swat r.swat; do
	cp $i $TMPINSTALLDIR/$INSTALL_BASE
done

# Create the package
pkgmk -o -d /tmp -b $TMPINSTALLDIR/$INSTALL_BASE -f prototype

if [ $? = 0 ]; then
	pkgtrans /tmp samba.pkg samba
fi

echo The samba package is in /tmp
