#
# spec file for package samba (Version HEAD) CVS
# 
# Copyright (c) 2002 SuSE Linux AG, Nuernberg, Germany.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
# packaged by Guenther Deschner <gd@suse.de> - work is not finished yet !

# neededforbuild  acl acl-devel attr attr-devel autoconf automake heimdal-devel heimdal-lib libxml2 libxml2-devel mysql-devel mysql-shared openldap2 openldap2-client openldap2-devel openssl openssl-devel popt popt-devel python python-devel readline readline-devel
# usedforbuild    aaa_base aaa_version acl attr bash bind9-utils bison cpio cpp cyrus-sasl db devs diffutils e2fsprogs file filesystem fileutils fillup findutils flex gawk gdbm-devel glibc glibc-devel glibc-locale gpm grep groff gzip kbd less libgcc libstdc++ libxcrypt m4 make man mktemp modutils ncurses ncurses-devel net-tools netcfg pam pam-devel pam-modules patch permissions ps rcs readline sed sendmail sh-utils shadow strace syslogd sysvinit tar texinfo textutils timezone unzip util-linux vim zlib-devel acl-devel attr-devel autoconf automake binutils bzip2 cracklib gcc gdbm gettext heimdal-devel heimdal-lib libtool libxml2 libxml2-devel mysql-devel mysql-shared openldap2 openldap2-client openldap2-devel openssl openssl-devel perl popt popt-devel python python-devel readline-devel rpm zlib


Vendor:		SuSE Linux AG, GS Berlin, Germany
Distribution:	SuSE Linux 8.1 (i386)
Name:		samba
Packager:	gd@suse.de
License:	GPL
Group:		Productivity/Networking/Samba
Url:		http://www.samba.org
Provides:	samba smbfs
Obsoletes:	samba-classic samba-ldap
Autoreqprov:	on
%define         smbwrap 0
%define		mit_kerberos 0
%define		heimdal_kerberos 1
%define		devel 0
%define         head 0
%define		python 1
%define		netatalk 0
%define		newsam 0
%define         samba_ver 3.0.0
Requires:	samba-client = %{samba_ver}
Version:        3.0.0
Release:	%(date +%%j)
Summary:	An SMB file server for Unix
Source:		%{name}-%{version}.tar.bz2
Source10:	%{name}-%{version}.files.tar.bz2
Source50:	http://prdownloads.sourceforge.net/openantivirus/samba-vscan-%{vscan_ver}.tar.bz2
Patch1:		%{name}-%{version}-pdb.diff
Patch10:	%{name}-%{version}-net_ads.diff
Patch22:	%{name}-%{version}-msdfs.diff
Patch30:	%{name}-%{version}-python.diff
BuildRoot:	%{_tmppath}/%{name}-%{version}-buildroot
%define		DOCDIR %{_defaultdocdir}/%{name}
%define		SWATDIR %{_datadir}/samba/swat
%define		vscan_ver 0.3.1
%define		vscan_modules fprot kaspersky mks openantivirus sophos trend
Patch51:	%{name}-%{version}-vscan.diff

%package client
Summary:	Samba client utilities
Autoreqprov:	on
Requires:	cups-libs
Obsoletes:	smbclnt samba-classic-client samba-ldap-client
Group:		Productivity/Networking/Samba

%package winbind
Requires:	samba-client samba
Summary:	Samba Winbind-package
Autoreqprov:	on
Group:		Productivity/Networking/Samba

%package utils
Summary:	Samba Testing Utilities
Autoreqprov:	on
Group:		Productivity/Networking/Samba

%package doc
Summary:	Samba Documentation
Autoreqprov:	on
Group:		Productivity/Networking/Samba

%package pdb
Summary:	Samba PDB-Modules
Autoreqprov:	on
Group:		Productivity/Networking/Samba

%package vfs
Summary:	Samba VFS-Modules
Autoreqprov:	on
Group:		Productivity/Networking/Samba

%if %{newsam} > 0
%package sam
Summary:	Samba SAM-Modules
Autoreqprov:	on
Group:		Productivity/Networking/Samba
%endif

%package vscan
Summary:	Samba VFS-Modules for Virusscanners
Autoreqprov:	on
Group:		Productivity/Networking/Samba
Version:	0.3.1

%package python
Summary:	Samba Python-Modules
Autoreqprov:	on
Group:		Productivity/Networking/Samba




%changelog
* Sat Nov 3 2001 - gd@suse.de
- start


%prep
[ $RPM_BUILD_ROOT = "/" ] && (echo "your buildroot is /" && exit 0) || rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT

%setup -n %{name}-%{samba_ver}
%setup -T -D -a 50
cp -ar samba-vscan-%{vscan_ver} examples/VFS/

# untar my configs
%setup -T -D -a 10

%if %{heimdal_kerberos} > 0
%patch1
%patch51
%endif
#%patch10
#%patch22
#%patch30

find . -name CVS -print | xargs rm -rf
find . -name ".cvsignore" -print | xargs rm -rf
find . -name "'*.gd'" -print | xargs rm -rvf
find . -name "'*.orig'" -print | xargs rm -rvf

%build %{name}-%{samba_ver}
%{?suse_update_config:%{suse_update_config -f}}
cd source
./autogen.sh
libtoolize --force --copy
autoconf
export CFLAGS="$RPM_OPT_FLAGS -Wall -O -D_GNU_SOURCE -D_LARGEFILE64_SOURCE"
%ifarch ppc64
export CFLAGS="$CFLAGS -mminimal-toc"
%endif
CONF_OPTS_BASIC="\
	--prefix=/usr \
	--libdir=/etc/samba \
	--localstatedir=/var/lib/samba \
	--mandir=%{_mandir} \
	--sbindir=/usr/sbin \
	--with-privatedir=/etc/samba \
	--with-piddir=/var/run/samba \
	--with-codepagedir=/usr/share/samba/codepages \
	--with-swatdir=/usr/share/samba/swat \
	--with-smbmount \
	--with-automount \
	--enable-cups \
	--with-msdfs \
	--with-vfs \
	--with-pam \
	--with-pam_smbpass \
	--with-utmp \
	--with-winbind \
	--with-tdbsam \
	--with-ldapsam \
%if %{smbwrap}
	--with-smbwrapper \
%endif
	--with-quotas \
	--with-acl-support \
	--with-python=python2.2 \
	--with-syslog \
"
CONF_OPTS_HEAD="\
	--with-sam \
"
CONF_OPTS_HEIMDAL_KERBEROS="\
	--with-krb5impl=heimdal \
"
CONF_OPTS_HEIMDAL_51_KERBEROS="\
	--with-krb5impl=heimdal \
	--with-krb5includes=/opt/heimdal-0.5.1/include \
	--with-krb5libs=/opt/heimdal-0.5.1/lib \
"
CONF_OPTS_MIT_KERBEROS="\
	--with-krb5impl=mit \
	--with-krb5includes=/usr/kerberos/include \
	--with-krb5libs=/usr/kerberos/lib \
"
CONF_OPTS_DEVEL="\
	--enable-developer \
	--enable-krb5developer \
	--with-profiling-data \
"
CONF_OPTS="$CONF_OPTS_BASIC"
%if %{head} > 0
CONF_OPTS="$CONF_OPTS $CONF_OPTS_HEAD"
%endif 
%if %{heimdal_kerberos} > 0
CONF_OPTS="$CONF_OPTS $CONF_OPTS_HEIMDAL_KERBEROS"
%endif 
%if %{mit_kerberos} > 0
CONF_OPTS="$CONF_OPTS $CONF_OPTS_MIT_KERBEROS"
%endif 
%if %{devel} > 0
CONF_OPTS="$CONF_OPTS $CONF_OPTS_DEVEL"
%endif 

./configure $CONF_OPTS

###	--with-ldapsam is now standard!
###	--with-sendfile-support ---default now
#	--with-nisplussam \
#	--with-nisplus_home \

# with the new passdb-code we can finaly compile several passdb-backends
# and make our choice at runtime. 
# HEAD and thus alpha21 no longer need this
#make proto

make \
	LOCKDIR=/var/lib/samba \
	LOGFILEBASE=/var/log/samba \
	SBINDIR=/usr/sbin \
	all \
	torture \
	nsswitch/libnss_wins.so \
	debug2html \
	libsmbclient \
	bin/profiles \
	everything

# everything = nsswitch smbwrapper smbtorture debug2html smbfilter nsswitch/libnss_wins.so

%if %{newsam} > 0
make bin/samtest 
%endif
make modules 

make -C tdb tdbdump tdbtest tdbtool tdbtorture 
# tdbbackup is now in main Makefile

make talloctort 

# VFS,PDB and SAM
EXAMPLEDIRS="pdb"
for i in $EXAMPLEDIRS; do make -C ../examples/$i; done

export USE_KAVPSHAREDLIB=0
for module in %{vscan_modules}; do 
	make -C ../examples/VFS/%{name}-vscan-%{vscan_ver}/${module}; 
done

# tim potters python
%if %{python} > 0
make python_ext
%endif



%install

mkdir -p \
	$RPM_BUILD_ROOT/usr/{bin,sbin} \
	$RPM_BUILD_ROOT/usr/share/{man,samba/{scripts,swat}} \
	$RPM_BUILD_ROOT/usr/lib/samba/{vfs,pdb,sam,vscan} \
	$RPM_BUILD_ROOT/usr/lib/python2.2/lib-dynload \
	$RPM_BUILD_ROOT/usr/include \
	$RPM_BUILD_ROOT/etc/{pam.d,init.d,samba} \
	$RPM_BUILD_ROOT/var/adm \
	$RPM_BUILD_ROOT/sbin \
	$RPM_BUILD_ROOT/lib/security \
	$RPM_BUILD_ROOT/%{DOCDIR} \
	$RPM_BUILD_ROOT/%{DOCDIR}-vscan \
	$RPM_BUILD_ROOT/var/spool/samba \
	$RPM_BUILD_ROOT/var/log/samba \
	$RPM_BUILD_ROOT/var/run/samba \
	$RPM_BUILD_ROOT/var/lib/samba/{netlogon,drivers/{W32X86,WIN40,W32ALPHA,W32MIPS,W32PPC},profiles}	

cd source/
make install \
	LIBDIR=$RPM_BUILD_ROOT/etc/samba \
	LOGFILEBASE=$RPM_BUILD_ROOT/var/log/samba \
	CONFIGFILE=$RPM_BUILD_ROOT/etc/samba/smb.conf \
	LMHOSTSFILE=$RPM_BUILD_ROOT/etc/samba/lmhosts \
	SWATDIR=$RPM_BUILD_ROOT/usr/share/samba/swat \
	SBINDIR=$RPM_BUILD_ROOT/usr/sbin \
	LOCKDIR=$RPM_BUILD_ROOT/var/lock/samba \
	CODEPAGEDIR=$RPM_BUILD_ROOT/usr/share/samba/codepages \
	DRIVERFILE=$RPM_BUILD_ROOT/etc/samba/printers.def \
	BINDIR=$RPM_BUILD_ROOT/usr/bin \
	SMB_PASSWD_FILE=$RPM_BUILD_ROOT/etc/samba/smbpasswd \
	TDB_PASSWD_FILE=$RPM_BUILD_ROOT/etc/samba/smbpasswd.tdb \
	MANDIR=$RPM_BUILD_ROOT/usr/share/man
cd ..

# utility scripts
%if %{head} > 0
scripts="creategroup cvslog.pl scancvslog.pl"
%else
scripts="scancvslog.pl"
%endif
for i in $scripts; do
	cp -a source/script/$i		$RPM_BUILD_ROOT/usr/share/samba/scripts/
done

# move the man-pages (ugly lang thing, fixed in alpha16)
#mv $RPM_BUILD_ROOT/usr/share/man/lang/*	$RPM_BUILD_ROOT/usr/share/man/

# configuration files
install -m 644 smb.conf*	$RPM_BUILD_ROOT/etc/samba/
install -m 644 shares.conf	$RPM_BUILD_ROOT/etc/samba/
install -m 644 lmhosts		$RPM_BUILD_ROOT/etc/samba/
install -m 600 smbpasswd -o root -g root  $RPM_BUILD_ROOT/etc/samba/

# pam
install -m 644 samba.pamd	$RPM_BUILD_ROOT/etc/pam.d/samba

# sambamount
ln -sf /usr/bin/smbmount	$RPM_BUILD_ROOT/sbin/mount.smbfs

# start scripts
install rc.smb			$RPM_BUILD_ROOT/etc/init.d/smb
ln -sf ../../etc/init.d/smb	$RPM_BUILD_ROOT/usr/sbin/rcsmb
install rc.smbfs		$RPM_BUILD_ROOT/etc/init.d/smbfs
ln -sf ../../etc/init.d/smbfs	$RPM_BUILD_ROOT/usr/sbin/rcsmbfs
install rc.winbind		$RPM_BUILD_ROOT/etc/init.d/winbind
ln -sf ../../etc/init.d/winbind	$RPM_BUILD_ROOT/usr/sbin/rcwinbind
install rc.wrepl		$RPM_BUILD_ROOT/etc/init.d/wrepl
ln -sf ../../etc/init.d/wrepl	$RPM_BUILD_ROOT/usr/sbin/rcwrepl

#### disabled for 8.0
### rc.config fragment
mkdir -p $RPM_BUILD_ROOT/var/adm/fillup-templates
cp rc.config.samba				$RPM_BUILD_ROOT/var/adm/fillup-templates
cp rc.config.winbind				$RPM_BUILD_ROOT/var/adm/fillup-templates
cp rc.config.wrepl				$RPM_BUILD_ROOT/var/adm/fillup-templates

# libnss_wins.so
cp source/nsswitch/libnss_wins.so		$RPM_BUILD_ROOT/lib/libnss_wins.so
ln -sf /lib/libnss_wins.so			$RPM_BUILD_ROOT/lib/libnss_wins.so.2

# winbind stuff
cp -a source/nsswitch/pam_winbind.so		$RPM_BUILD_ROOT/lib/security/
cp -a source/nsswitch/libnss_winbind.so		$RPM_BUILD_ROOT/lib/
cp -a source/bin/winbindd			$RPM_BUILD_ROOT/usr/sbin/
ln -sf /lib/libnss_winbind.so			$RPM_BUILD_ROOT/lib/libnss_winbind.so.2

# pam_smbpass
cp -a source/bin/pam_smbpass.so			$RPM_BUILD_ROOT/lib/security/

# smbfilter
cp -a source/bin/smbfilter			$RPM_BUILD_ROOT/usr/bin/


%{?suse_check}

## install libsmbclient
install -m0755 source/bin/{libsmbclient.so,libsmbclient.a}	$RPM_BUILD_ROOT/%{_libdir}
ln -s /usr/lib/libsmbclient.so			$RPM_BUILD_ROOT/%{_libdir}/libsmbclient.so.0
install -m0644 source/include/libsmbclient.h	$RPM_BUILD_ROOT/%{_includedir}

# install smbtorture and other test-programs
install -m0755 source/bin/smbtorture		$RPM_BUILD_ROOT/usr/bin/
install -m0755 source/bin/talloctort		$RPM_BUILD_ROOT/usr/bin/
install -m0755 source/bin/{msgtest,masktest,locktest*}	$RPM_BUILD_ROOT/usr/bin/
install -m0755 source/bin/{vfstest,nsstest}	$RPM_BUILD_ROOT/usr/bin/
%if %{head} > 0
%if %{newsam} > 0
install -m0755 source/bin/samtest		$RPM_BUILD_ROOT/usr/bin/ 
%endif
%endif

# install tdb tools
install -m0755 source/tdb/{tdbdump,tdbtest,tdbtool,tdbtorture}	$RPM_BUILD_ROOT/usr/bin/


# install VFS-modules
%if %{head} > 0
install -m0755 source/bin/developer.so		$RPM_BUILD_ROOT/%{_libdir}/samba/vfs/
#install -m0755 examples/VFS/block/block.so	$RPM_BUILD_ROOT/%{_libdir}/samba/vfs/
#install -m0755 examples/VFS/skel.so		$RPM_BUILD_ROOT/%{_libdir}/samba/vfs/
%else
#install -m0755 examples/VFS/block/block.so	$RPM_BUILD_ROOT/%{_libdir}/samba/vfs/
#install -m0755 examples/VFS/skel.so		$RPM_BUILD_ROOT/%{_libdir}/samba/vfs/
%endif
install -m0755 source/bin/vfs_audit.so		$RPM_BUILD_ROOT/%{_libdir}/samba/vfs/
install -m0755 source/bin/vfs_extd_audit.so	$RPM_BUILD_ROOT/%{_libdir}/samba/vfs/
install -m0755 source/bin/vfs_recycle.so	$RPM_BUILD_ROOT/%{_libdir}/samba/vfs/
%if %{netatalk}
install -m0755 source/bin/vfs_netatalk.so	$RPM_BUILD_ROOT/%{_libdir}/samba/vfs/
%endif

# install PDB-modules
%if %{head} > 0
install -m0755 source/bin/xml.so		$RPM_BUILD_ROOT/%{_libdir}/samba/pdb/
install -m0755 source/bin/mysql.so		$RPM_BUILD_ROOT/%{_libdir}/samba/pdb/
%else
install -m0755 source/bin/pdb_xml.so		$RPM_BUILD_ROOT/%{_libdir}/samba/pdb/
install -m0755 source/bin/pdb_mysql.so		$RPM_BUILD_ROOT/%{_libdir}/samba/pdb/
%endif
install -m0755 examples/pdb/pdb_test.so		$RPM_BUILD_ROOT/%{_libdir}/samba/pdb/

# install SAM-modules
%if %{head} > 0
%if %{newsam} > 0
install -m0755 examples/sam/sam_skel.so		$RPM_BUILD_ROOT/%{_libdir}/samba/sam/
%endif
%endif

# install VSCAN-vfs-modules
install -m0755 examples/VFS/%{name}-vscan-%{vscan_ver}/*/*.so	$RPM_BUILD_ROOT/%{_libdir}/samba/vscan/

# make examples clean
VFS="$RPM_BUILD_DIR/%{name}-%{samba_ver}/examples/VFS"
VSCAN="$VFS/%{name}-vscan-%{vscan_ver}"
PDB="$RPM_BUILD_DIR/%{name}-%{samba_ver}/examples/pdb"
%if %{head} > 0
%if %{newsam} > 0
SAM="$RPM_BUILD_DIR/%{name}-%{samba_ver}/examples/sam"
%endif
%endif
dirs="$PDB $SAM"
(for i in $dirs; do make -C $i clean; done)
(for i in %{vscan_modules}; do make -C $VSCAN/$i clean; done)

%if %{python} > 0
# install python
cp -a source/build/lib.*/samba 			$RPM_BUILD_ROOT/usr/lib/python2.2/lib-dynload/
%endif

# whats this ?
install -m0755 source/bin/debug2html		$RPM_BUILD_ROOT/usr/bin/

%if %{smbwrap}
# install smbwrapper
install -m0755 source/bin/smbwrapper.so		$RPM_BUILD_ROOT/%{_libdir}/samba/
install -m0755 source/bin/smbsh		        $RPM_BUILD_ROOT/usr/bin/
%endif

# finally obsolete with alpha17 makefile
# install unicode-codepages
#install -m0755 source/codepages/{lowcase,upcase,valid}.dat	$RPM_BUILD_ROOT/etc/samba/

# cleanup docs
rm -rf docs/*.[0-9]
chmod 644 `find docs examples -type f`
chmod 755 `find docs examples -type d`
mv COPYING Manifest README Read-Manifest-Now Roadmap WHATSNEW.txt $RPM_BUILD_ROOT/%{DOCDIR}/
cp source/msdfs/README 		$RPM_BUILD_ROOT/%{DOCDIR}/README.msdfs
#cp source/nsswitch/README	$RPM_BUILD_ROOT/%{DOCDIR}/README.nsswitch
cp source/smbwrapper/README 	$RPM_BUILD_ROOT/%{DOCDIR}/README.smbwrapper
cp -a docs/*			$RPM_BUILD_ROOT/%{DOCDIR}
cp -a examples/			$RPM_BUILD_ROOT/%{DOCDIR}
# save space...
rm -r \
	$RPM_BUILD_ROOT/%{SWATDIR}/using_samba 
ln -s %{DOCDIR}/htmldocs/using_samba $RPM_BUILD_ROOT/%{SWATDIR}


%post
###### disabled for 8.1
###echo "Updating etc/rc.config..."
##if [ -x bin/fillup ] ; then
##  bin/fillup -q -d = etc/rc.config var/adm/fillup-templates/rc.config.samba
##  bin/fillup -q -d = etc/rc.config var/adm/fillup-templates/rc.config.winbind
##else
##  echo "ERROR: fillup not found. This should not happen. Please compare"
##  echo "etc/rc.config and var/adm/fillup-templates/rc.config.samba and"
##  echo "var/adm/fillup-templates/rc.config.winbind and update by hand."
##fi
mkdir -p $RPM_BUILD_ROOT/var/adm/notify/messages
cat << EOF > var/adm/notify/messages/samba-notify
Achtung!

This is %{name}-%{samba_ver}. Please do not run on production systems.

You have been warned.
EOF

# Initialize runlevel links
#
%{fillup_and_insserv smb}
#sbin/insserv /etc/init.d/smb

%post client
#sbin/insserv /etc/init.d/smbfs
%{fillup_and_insserv -fpy smbfs}
%{fillup_only -ans samba client}

%postun
%{insserv_cleanup}
#sbin/insserv /etc/init.d/

%postun client
%{insserv_cleanup}
#sbin/insserv /etc/init.d/

%post winbind
%{fillup_and_insserv winbind}
#sbin/insserv /etc/init.d/winbind

%postun winbind
%{insserv_cleanup}
#sbin/insserv /etc/init.d/

%clean
#make -C source realclean

%files
%config(noreplace) /etc/samba/smbpasswd
%config /etc/pam.d/samba
%config /etc/init.d/smb
%config /etc/init.d/wrepl
#/usr/bin/make_printerdef
/usr/bin/addtosmbpass
/usr/bin/convert_smbpasswd
/usr/bin/smbgroupedit
/usr/bin/ntlm_auth
/usr/bin/profiles
/usr/bin/smbfilter
/usr/bin/smbpasswd
/usr/bin/smbstatus
/usr/bin/testparm
/usr/bin/testprns
#%doc %{_mandir}/man1/smbrun.1.gz
%doc %{_mandir}/man1/smbsh.1.gz
%doc %{_mandir}/man1/smbstatus.1.gz
%doc %{_mandir}/man1/testparm.1.gz
%doc %{_mandir}/man1/testprns.1.gz
%doc %{_mandir}/man5/smbpasswd.5.gz
%doc %{_mandir}/man7/samba.7.gz
%doc %{_mandir}/man8/nmbd.8.gz
%doc %{_mandir}/man8/smbd.8.gz
%doc %{_mandir}/man8/smbgroupedit.8.gz
%doc %{_mandir}/man8/smbpasswd.8.gz
%doc %{_mandir}/man8/swat.8.gz
/usr/sbin/nmbd
/usr/sbin/smbd
/usr/sbin/swat
/usr/sbin/wrepld
/usr/sbin/rcsmb
/usr/sbin/rcwrepl
#/var/adm/fillup-templates/rc.config.samba
/var/log/samba
/var/spool/samba
/var/run/samba
/var/lib/samba
/usr/share/samba
/lib/security/pam_smbpass.so

%files client
%config(noreplace) /etc/samba/smb.conf
%config(noreplace) /etc/samba/lmhosts
/etc/samba/lowcase.dat
/etc/samba/upcase.dat
/etc/samba/valid.dat
%config /etc/init.d/smbfs
/usr/sbin/rcsmbfs
/sbin/mount.smbfs
/usr/bin/findsmb
/usr/bin/net
/usr/bin/nmblookup
/usr/bin/pdbedit
/usr/bin/rpcclient
/usr/bin/smbcacls
/usr/bin/smbcontrol
/usr/bin/smbclient
/usr/bin/smbmnt
/usr/bin/smbmount
%if %{smbwrap}
/usr/bin/smbsh
%endif
/usr/bin/smbumount
/usr/bin/smbspool
/usr/bin/smbtar
/usr/bin/smbtree
%doc %{_mandir}/man1/nmblookup.1.gz
%doc %{_mandir}/man1/rpcclient.1.gz
%doc %{_mandir}/man1/smbclient.1.gz
%doc %{_mandir}/man1/smbcacls.1.gz
%doc %{_mandir}/man1/smbcontrol.1.gz
%doc %{_mandir}/man1/smbtar.1.gz
%doc %{_mandir}/man5/lmhosts.5.gz
%doc %{_mandir}/man5/smb.conf.5.gz
%doc %{_mandir}/man8/net.8.gz
%doc %{_mandir}/man8/pdbedit.8.gz
%doc %{_mandir}/man8/smbmnt.8.gz
%doc %{_mandir}/man8/smbmount.8.gz
%doc %{_mandir}/man8/smbspool.8.gz
%doc %{_mandir}/man8/smbumount.8.gz
/usr/include/libsmbclient.h
%if %{smbwrap}
/usr/lib/samba/smbwrapper.so
%endif
/usr/lib/libsmbclient.a
/usr/lib/libsmbclient.so
/usr/lib/libsmbclient.so.0

%files winbind
%config(noreplace) /etc/samba/smb.conf.winbind
%config /etc/init.d/winbind
%doc %{_mandir}/man1/wbinfo.1.gz
%doc %{_mandir}/man8/winbindd.8.gz
/usr/bin/wbinfo
%if %{head} > 0
/usr/bin/ntlm_auth
%endif
/usr/sbin/winbindd
/usr/sbin/rcwinbind
#/var/adm/fillup-templates/rc.config.winbind
/lib/security/pam_winbind.so
/lib/libnss_winbind.so
/lib/libnss_winbind.so.2
/lib/libnss_wins.so
/lib/libnss_wins.so.2

%files utils
/usr/bin/smbtorture
/usr/bin/msgtest
/usr/bin/masktest
/usr/bin/locktest
/usr/bin/locktest2
/usr/bin/debug2html
/usr/bin/talloctort
/usr/bin/tdbbackup
/usr/bin/tdbdump  
/usr/bin/tdbtest  
/usr/bin/tdbtool  
/usr/bin/tdbtorture
/usr/bin/vfstest
/usr/bin/nsstest
%if %{head} > 0
%if %{newsam} > 0
/usr/bin/samtest
%endif
/usr/bin/profiles
/usr/bin/editreg
%endif
%doc %{_mandir}/man1/vfstest.1.gz

%files doc
%docdir %{DOCDIR}
%{DOCDIR}

%files pdb
/usr/lib/samba/pdb
%doc examples/pdb/*

%files vfs
/usr/lib/samba/vfs
%doc examples/VFS/README*
%doc examples/VFS/Makefile*
#doc examples/VFS/audit*
#%doc examples/VFS/block*
#doc examples/VFS/netatalk*
#doc examples/VFS/recycle*
%doc examples/VFS/skel*

%if %{newsam} > 0
%files sam
/usr/lib/samba/sam
%if %{head} > 0
%doc examples/sam/*
%endif
%endif

%files vscan
/usr/lib/samba/vscan
%doc %{name}-vscan-%{vscan_ver}/{AUTHORS,COPYING,ChangeLog,FAQ,NEWS,README,TODO}


%files python
%doc source/python/README 
%if %{python} > 0
/usr/lib/python2.2/lib-dynload/samba
%doc source/python/examples 
%doc source/python/gprinterdata
%doc source/python/gtdbtool
%doc source/python/gtkdictbrowser.py
%if %{head} > 0
%doc source/python/gtkdictbrowser.pyc
%doc source/python/printerdata.pyc
%endif
%endif

%description
Samba is a suite of programs which work together to allow clients to
access Unix filespace and printers via the SMB protocol (Server Message
Block). 
In practice, this means that you can redirect disks and printers to
Unix disks and printers from LAN Manager clients, Windows for
Workgroups 3.11 clients, Windows'95 clients, Windows NT clients
and OS/2 clients. There is
also a Unix client program supplied as part of the suite which allows
Unix users to use an ftp-like interface to access filespace and
printers on any other SMB server.
Samba includes the following programs (in summary):
* smbd, the SMB server. This handles actual connections from clients.
* nmbd, the Netbios name server, which helps clients locate servers.
* smbclient, the Unix-hosted client program.
* smbrun, a little 'glue' program to help the server run external
programs. 
* testprns, a program to test server access to printers.
* testparm, a program to test the Samba configuration file for correctness.
* smb.conf, the Samba configuration file.
* smbprint, a sample script to allow a Unix host to use smbclient
to print to an SMB server.
The suite is supplied with full source and is GPLed.
This package expects its config file under /etc/smb.conf .

Authors:
--------
    Andrew Tridgell <Andrew.Tridgell@anu.edu.au>
    Karl Auer <Karl.Auer@anu.edu.au>
    Jeremy Allison <jeremy@netcom.com>

SuSE series: n


%description client
This package contains all programs, that are needed to act as a samba
client. This includes also smbmount, of course.

Authors:
--------
    Andrew Tridgell <Andrew.Tridgell@anu.edu.au>
    Karl Auer <Karl.Auer@anu.edu.au>
    Jeremy Allison <jeremy@netcom.com>

SuSE series: n


%description winbind
This is the winbind-daemon and the wbinfo-tool.

%description utils
Some of the debug-tools for developpers.
Contains:
	- debug2html
	- locktest
	- locktest2
	- masktest
	- msgtest
	- smbtorture
	- talloctort
	- several tdb-tools

%description doc
The Samba Documentation.

%description vfs
The Samba VFS-Modules.

%description pdb
The Samba PDB-Modules.

%if %{newsam} > 0
%description sam
The Samba SAM-Modules.
%endif

%description vscan
The Samba VFS-Modules for Virusscanners.

%description python
The Samba python-Modules.
