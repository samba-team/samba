#
# spec file for package samba3 (Version 3.0.0rc1cvs)
#
# Copyright (c) 2003 SuSE Linux AG, Nuernberg, Germany.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
# Please submit bugfixes or comments via http://www.suse.de/feedback/
#
# Note: The Samba3 tarball should be called: samba3-3.0.0.tar.bz2
#

# neededforbuild  XFree86-libs autoconf automake cups-devel cups-libs dialog docbook-utils docbook-xsl-stylesheets docbook_4 ed freetype2 ghostscript-fonts-std ghostscript-library ghostscript-x11 glib heimdal heimdal-devel heimdal-lib iso_ent libacl libacl-devel libattr libattr-devel libgimpprint libpng libtiff libxml2 libxml2-devel libxslt mysql-devel mysql-shared openldap2 openldap2-client openldap2-devel openssl openssl-devel popt popt-devel python python-devel readline readline-devel te_etex te_latex te_pdf tetex xmlcharent
# usedforbuild    aaa_base acl attr bash bind9-utils bison coreutils cpio cpp cvs cyrus-sasl2 db devs diffutils e2fsprogs file filesystem fillup findutils flex gawk gdbm-devel glibc glibc-devel glibc-locale gpm grep groff gzip info insserv kbd less libacl libattr libgcc libstdc++ libxcrypt m4 make man mktemp modutils ncurses ncurses-devel net-tools netcfg pam pam-devel pam-modules patch permissions ps rcs readline sed sendmail shadow strace syslogd sysvinit tar texinfo timezone unzip util-linux vim zlib zlib-devel XFree86-libs autoconf automake binutils bzip2 cracklib cups-devel cups-libs dialog docbook-utils docbook-xsl-stylesheets docbook_4 ed freetype2 gcc gdbm gettext ghostscript-fonts-std ghostscript-library ghostscript-x11 glib heimdal heimdal-devel heimdal-lib iso_ent libacl-devel libattr-devel libgimpprint libpng libtiff libtool libxml2 libxml2-devel libxslt mysql-devel mysql-shared openldap2 openldap2-client openldap2-devel openssl openssl-devel perl popt popt-devel python python-devel readline-devel rpm te_ams te_etex te_latex te_pdf tetex xmlcharent

Name:         samba3
Vendor:       Samba Team
License:      GPL
Group:        Productivity/Networking/Samba
Url:          http://www.samba.org
Provides:     samba smbfs samba3
Requires:     samba3-client 
Obsoletes:    samba-classic samba-ldap
Autoreqprov:  on
%define		krb_heimdal_05	0
%define		new_heimdal	/opt/heimdal
%define		new_sasl	/opt/sasl
%define		new_openldap	/opt/openldap
%define		new_glibc	0
Version:      3.0.0
Release:      %(date +%%j)
%define         head 		0
%define         samba_ver 3.0.0
%define		samba_release 	0
%define		ul_version	0
%define         suse_ver 820
%define         python_ver	python2.2
%if %{suse_ver} > 810
%define		new_glibc	1
%endif
%if %{suse_ver} > 821
%define         python_ver 	python2.3
%endif
%define		make_cifsvfs	1
%define		make_devel 	0
%define		make_doc 	0
%define		make_python 	1
%define		make_shared_mod	0
%define		make_smbwrap	1
# vscan has not yet updated to the new vfs-api
%define		make_vscan 	0
%define		make_wrepld 	1
%define		use_keytab 	0
Summary:      samba3
Source:       %{name}-%{version}.tar.bz2
Source10:     %{name}-%{version}.files.tar.bz2
Source50:     samba-vscan-%{vscan_ver}.tar.bz2
Patch1:       %{name}-%{version}-Makefiles-heimdal.diff
Patch2:       samba-mutual-auth.diff
Patch29:      %{name}-com_err.diff
Patch30:      %{name}-%{version}-heimdal-06.diff
Patch31:      %{name}-%{version}-pdb.diff
Patch32:      %{name}-net_ads_password.diff
Patch33:      %{name}-Makefile.diff
Patch34:      %{name}-smbwrapper.diff
Patch51:      %{name}-vscan.diff
BuildRoot:    %{_tmppath}/%{name}-%{version}-build
%define		DOCDIR 		%{_defaultdocdir}/%{name}
%define		DOCBOOKDIR 	%{_defaultdocdir}/%{name}/docbook
%define		SWATDIR 	%{_datadir}/samba/swat
%define		vscan_ver	0.3.2b
%define		vscan_modules	fprot icap mks openantivirus sophos trend
#not pdb_nisplussam
%define 	pdb_modules	pdb_xml,pdb_mysql,pdb_ldap,pdb_smbpasswd,pdb_tdbsam,pdb_unix,pdb_guest,pdb_nisplussam
%define		rpc_modules	rpc_lsa,rpc_samr,rpc_reg,rpc_wks,rpc_net,rpc_dfs,rpc_srv,rpc_spoolss
%define		auth_modules	auth_rhosts,auth_sam,auth_unix,auth_winbind,auth_server,auth_domain,auth_builtin
%define		vfs_modules	vfs_recycle,vfs_audit,vfs_extd_audit,vfs_netatalk,vfs_fake_perms
%define		idmap_modules	idmap_winbind,idmap_ldap,idmap_tdb
%define		charset_modules	charset_weird
%package client
Summary:      samba3-client
Autoreqprov:  on
Requires:     cups-libs
Obsoletes:    smbclnt samba-classic-client samba-ldap-client
Provides:     samba-client samba3-client
Group:        Productivity/Networking/Samba
%package winbind
Requires:     samba-client samba
Summary:      samba3-winbind
Autoreqprov:  on
Group:        Productivity/Networking/Samba
%package utils
Summary:      samba3-utils
Autoreqprov:  on
Group:        Productivity/Networking/Samba
%package doc
Summary:      samba3-doc
Autoreqprov:  on
Group:        Productivity/Networking/Samba
%package docbook
Summary:      samba3-docbook
Autoreqprov:  on
Group:        Productivity/Networking/Samba
%package pdb
Summary:      samba3-pdb
Autoreqprov:  on
Group:        Productivity/Networking/Samba
%if %{make_cifsvfs}
%package cifsmount
Summary:      samba3-cifsmount
Autoreqprov:  on
Group:        Productivity/Networking/Samba
Url:          http://us1.samba.org/samba/Linux_CIFS_client.html
%endif
%if %{make_vscan}
%package vscan
Summary:      samba3-vscan
Autoreqprov:  on
Group:        Productivity/Networking/Samba
Version:      0.3.2a
Release:      0
Url:          http://www.openantivirus.org/
%endif
%if %{make_wrepld}
%package wrepld
Summary:      samba3-wrepld
Autoreqprov:  on
Group:        Productivity/Networking/Samba
%endif
%if %{make_python}
%package python
Summary:      samba3-python
Autoreqprov:  on
Group:        Productivity/Networking/Samba
%endif
%package -n libsmbclient
Summary:      Samba client library
Autoreqprov:  on
Group:        System/Libraries
%package -n libsmbclient-devel
Summary:      Libraries and header files to develop programs with smbclient support
Autoreqprov:  on
Group:        Development/Libraries/C and C++
%prep
[ $RPM_BUILD_ROOT = "/" ] && (echo "your buildroot is /" && exit 0) || rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT
%setup -n %{name}-%{samba_ver}
%setup -T -D -a 50
cp -ar samba-vscan-%{vscan_ver} examples/VFS/
# untar my configs
%setup -T -D -a 10
###########
### PATCHES
###########
# Makefiles-heimdal.diff
%patch1
%if %{use_keytab}
# luke howards keytab-patch
%patch2
%endif
# some com_err fixes
%patch29
%if %{suse_ver} > 821
%patch30
%endif
# vscan patch
%patch51
# net ads password
%patch32
# temp Makefile (show more libs)
%patch33
# temp pdb-test.c
%patch31
# smbwrapper should use LIBDIR not BINDIR
%patch34
#find . -name CVS -print | xargs rm -rf
#find . -name ".cvsignore" -print | xargs rm -rf
find . -name "*.gd" -print | xargs rm -rvf
find . -name "*.orig" -print | xargs rm -rvf
%if %{ul_version} >= 1
        echo '#define VERSION "%samba_ver-UL"' > source/include/version.h
%else
        echo '#define VERSION "%samba_ver-SuSE"' > source/include/version.h
%endif

%build %{name}-%{samba_ver}
%{?suse_update_config:%{suse_update_config -f}}
cd source
./autogen.sh
export CFLAGS="$RPM_OPT_FLAGS -Wall -O -D_GNU_SOURCE -D_LARGEFILE64_SOURCE"
# debugging symbols
%if %{make_devel}
export CFLAGS="$RPM_OPT_FLAGS -g -Wall -O -D_GNU_SOURCE -D_LARGEFILE64_SOURCE"
%endif
%if %{krb_heimdal_05} 
export CFLAGS="$CFLAGS -I./include -I%{new_heimdal}/include "
export CFLAGS="$CFLAGS -I%{new_openldap}/include "
export CFLAGS="$CFLAGS -I%{new_sasl}/include "
export LDFLAGS="$LDFLAGS -Wl,-rpath %{new_heimdal}/lib" 
export LDFLAGS="$LDFLAGS -Wl,-rpath %{new_openldap}/lib"
export LDFLAGS="$LDFLAGS -Wl,-rpath %{new_sasl}/lib" 
%endif
%ifarch ppc64
export CFLAGS="$CFLAGS -mminimal-toc"
%endif
CONF_OPTS="\
	--enable-cups \
	--libdir=/usr/lib/samba \
	--localstatedir=/var/lib/samba \
	--mandir=%{_mandir} \
	--prefix=/usr \
	--sbindir=/usr/sbin \
	--sysconfdir=/etc/samba \
	--with-acl-support \
	--with-automount \
	--with-configdir=/etc/samba \
	--with-lockdir=/var/lib/samba \
	--with-logfilebase=/var/log/samba \
	--with-msdfs \
	--with-pam \
	--with-pam_smbpass \
	--with-piddir=/var/run/samba \
	--with-privatedir=/etc/samba \
	--with-quotas \
	--with-smbmount \
	--with-swatdir=/usr/share/samba/swat \
	--with-syslog \
	--with-utmp \
	--with-vfs \
	--with-winbind \
	--with-tdbsam \
	--with-expsam=xml,mysql \
	--with-profiling-data \
%if %{use_keytab}
	--enable-keytab \
%endif
%if %{make_smbwrap}
	--with-smbwrapper \
%endif
%if %{make_python}
	--with-python=%{python_ver} \
%endif
%if %{make_shared_mod} 
	--with-shared-modules=%{pdb_modules},%{rpc_modules} \
%endif
%if %{make_devel} 
	--enable-developer \
	--enable-krb5developer \
%endif
"
#	--with-nisplus-home \
# make sure we have a chance to find the krb5-config-tool
export PATH="$PATH:/usr/lib/heimdal/bin"
./configure $CONF_OPTS
make \
	all \
	torture \
	nsswitch/libnss_wins.so \
	debug2html \
	libsmbclient \
	everything \
	bin/editreg
# everything = nsswitch smbwrapper smbtorture debug2html smbfilter nsswitch/libnss_wins.so
make modules 
make -C tdb tdbdump tdbtest tdbtool tdbtorture 
make talloctort 
%if %{make_wrepld}
make bin/wrepld
%endif
%if %{make_doc}
pushd `pwd`
cd ../docs/docbook
autoconf -f
./configure
# gracefully ignore errors...
make -i manpages html html-single pdf htmlfaq htmlman
# ps is not necessary, txt neither
# everything = manpages ps pdf html-single html htmlman txt htmlfaq 
popd
%endif
# make examples in VFS,PDB 
pushd `pwd`
cd ../examples/VFS/
sh -x autogen.sh
./configure
popd
EXAMPLEDIRS="pdb VFS"
for i in $EXAMPLEDIRS; do make -C ../examples/$i; done
%if %{make_vscan}
export USE_KAVPSHAREDLIB=0
export USE_INCLMKSDLIB=1
for module in %{vscan_modules}; do 
	make -C ../examples/VFS/samba-vscan-%{vscan_ver}/${module}; 
done
%endif
%if %{make_python}
make python_ext
%endif
%if %{make_cifsvfs}
cd client
export CFLAGS="$RPM_OPT_FLAGS -Wall -O -D_GNU_SOURCE -D_LARGEFILE64_SOURCE"
gcc mount.cifs.c -o mount.cifs
cd ..
%endif

%install
mkdir -p \
	$RPM_BUILD_ROOT/%{DOCDIR} \
	$RPM_BUILD_ROOT/%{DOCDIR}-vscan \
	$RPM_BUILD_ROOT/%{DOCDIR}/docbook \
	$RPM_BUILD_ROOT/etc/{pam.d,init.d,samba} \
	$RPM_BUILD_ROOT/lib/security \
	$RPM_BUILD_ROOT/sbin \
	$RPM_BUILD_ROOT/usr/include \
	$RPM_BUILD_ROOT/usr/lib/%{python_ver}/lib-dynload \
	$RPM_BUILD_ROOT/usr/lib/samba/{vfs,pdb,vscan,rpc,auth,charset,idmap} \
	$RPM_BUILD_ROOT/usr/share/{man,samba/swat} \
	$RPM_BUILD_ROOT/usr/{bin,sbin} \
	$RPM_BUILD_ROOT/var/adm \
	$RPM_BUILD_ROOT/var/lib/samba/{netlogon,drivers/{W32X86,WIN40,W32ALPHA,W32MIPS,W32PPC},profiles} \
	$RPM_BUILD_ROOT/var/log/samba \
	$RPM_BUILD_ROOT/var/run/samba \
	$RPM_BUILD_ROOT/var/spool/samba 
cd source/
make install \
	LIBDIR=$RPM_BUILD_ROOT/usr/lib/samba \
	LOGFILEBASE=$RPM_BUILD_ROOT/var/log/samba \
	CONFIGFILE=$RPM_BUILD_ROOT/etc/samba/smb.conf \
	LMHOSTSFILE=$RPM_BUILD_ROOT/etc/samba/lmhosts \
	SWATDIR=$RPM_BUILD_ROOT/usr/share/samba/swat \
	SBINDIR=$RPM_BUILD_ROOT/usr/sbin \
	LOCKDIR=$RPM_BUILD_ROOT/var/lib/samba \
	DRIVERFILE=$RPM_BUILD_ROOT/etc/samba/printers.def \
	BINDIR=$RPM_BUILD_ROOT/usr/bin \
	SMB_PASSWD_FILE=$RPM_BUILD_ROOT/etc/samba/smbpasswd \
	MANDIR=$RPM_BUILD_ROOT/usr/share/man
make installmodules \
	LIBDIR=$RPM_BUILD_ROOT/usr/lib/samba 
cd ..
# utility scripts
%if %{head}
scripts="creategroup cvslog.pl scancvslog.pl"
%else
scripts="scancvslog.pl"
%endif
mkdir -p examples/scripts
for i in $scripts; do
	cp -a source/script/$i		examples/scripts/
done
# configuration files
%if %{ul_version} >= 1
        SUFFIX="UnitedLinux"
%else
        SUFFIX="SuSE"
%endif
cat smb.conf.vendor | egrep -v '(^$$|^#)' > smb.conf
mv smb.conf.vendor examples/smb.conf.${SUFFIX}
install -m 644 smb.conf*	$RPM_BUILD_ROOT/etc/samba/
install -m 644 lmhosts		$RPM_BUILD_ROOT/etc/samba/
install -m 644 smbusers		$RPM_BUILD_ROOT/etc/samba/
install -m 600 smbpasswd -o root -g root  $RPM_BUILD_ROOT/etc/samba/
install -m 600 smbfstab -o root -g root  $RPM_BUILD_ROOT/etc/samba/
# pam
install -m 644 samba.pamd	$RPM_BUILD_ROOT/etc/pam.d/samba
# sambamount
ln -sf /usr/bin/smbmount	$RPM_BUILD_ROOT/sbin/mount.smbfs
#cifsmount
%if %{make_cifsvfs}
install -m755 source/client/mount.cifs	$RPM_BUILD_ROOT/sbin
%endif
# start scripts
install rc.smb			$RPM_BUILD_ROOT/etc/init.d/smb
ln -sf ../../etc/init.d/smb	$RPM_BUILD_ROOT/usr/sbin/rcsmb
install rc.nmb			$RPM_BUILD_ROOT/etc/init.d/nmb
ln -sf ../../etc/init.d/nmb	$RPM_BUILD_ROOT/usr/sbin/rcnmb
install rc.smbfs		$RPM_BUILD_ROOT/etc/init.d/smbfs
ln -sf ../../etc/init.d/smbfs	$RPM_BUILD_ROOT/usr/sbin/rcsmbfs
install rc.winbind		$RPM_BUILD_ROOT/etc/init.d/winbind
ln -sf ../../etc/init.d/winbind	$RPM_BUILD_ROOT/usr/sbin/rcwinbind
%if %{make_wrepld}
install rc.wrepl		$RPM_BUILD_ROOT/etc/init.d/wrepl
ln -sf ../../etc/init.d/wrepl	$RPM_BUILD_ROOT/usr/sbin/rcwrepl
cp -a source/bin/wrepld		$RPM_BUILD_ROOT/usr/sbin/
%endif
# libnss_wins.so
cp source/nsswitch/libnss_wins.so		$RPM_BUILD_ROOT/lib/libnss_wins.so.2
ln -sf /lib/libnss_wins.so.2			$RPM_BUILD_ROOT/lib/libnss_wins.so
# winbind stuff
cp -a source/nsswitch/pam_winbind.so		$RPM_BUILD_ROOT/lib/security/
cp -a source/nsswitch/libnss_winbind.so		$RPM_BUILD_ROOT/lib/libnss_winbind.so.2
cp -a source/bin/winbindd			$RPM_BUILD_ROOT/usr/sbin/
ln -s /lib/libnss_winbind.so.2			$RPM_BUILD_ROOT/lib/libnss_winbind.so
# pam_smbpass
cp -a source/bin/pam_smbpass.so			$RPM_BUILD_ROOT/lib/security/
# smbfilter
cp -a source/bin/smbfilter			$RPM_BUILD_ROOT/usr/bin/
# editreg
cp -a source/bin/editreg			$RPM_BUILD_ROOT/usr/bin/
# install libsmbclient
install -m0755 source/bin/libsmbclient.a	$RPM_BUILD_ROOT/%{_libdir}
install -m0755 source/bin/libsmbclient.so	$RPM_BUILD_ROOT/%{_libdir}/libsmbclient.so.0
ln -s /usr/lib/libsmbclient.so.0		$RPM_BUILD_ROOT/%{_libdir}/libsmbclient.so
install -m0644 source/include/libsmbclient.h	$RPM_BUILD_ROOT/%{_includedir}
# install nsswitch-headers (for squid, etc.)
mkdir -p $RPM_BUILD_ROOT/%{_includedir}/samba/nsswitch
cp source/nsswitch/*.h				$RPM_BUILD_ROOT/%{_includedir}/samba/nsswitch/
# install smbtorture and other test-programs
install -m0755 source/bin/smbtorture		$RPM_BUILD_ROOT/usr/bin/
install -m0755 source/bin/talloctort		$RPM_BUILD_ROOT/usr/bin/
install -m0755 source/bin/{msgtest,masktest,locktest*}	$RPM_BUILD_ROOT/usr/bin/
install -m0755 source/bin/{vfstest,nsstest}	$RPM_BUILD_ROOT/usr/bin/
# install tdb tools
install -m0755 source/tdb/{tdbdump,tdbtest,tdbtool,tdbtorture}	$RPM_BUILD_ROOT/usr/bin/
# install VFS-modules
install -m0755 examples/VFS/*.so		$RPM_BUILD_ROOT/%{_libdir}/samba/vfs/
# install PDB-modules
install -m0755 examples/pdb/pdb_test.so		$RPM_BUILD_ROOT/%{_libdir}/samba/pdb/
%if %{make_vscan}
# install VSCAN-vfs-modules
install -m0755 examples/VFS/samba-vscan-%{vscan_ver}/*/*.so	$RPM_BUILD_ROOT/%{_libdir}/samba/vscan/
%endif
# make examples clean
VFS="$RPM_BUILD_DIR/%{name}-%{samba_ver}/examples/VFS"
VSCAN="$VFS/samba-vscan-%{vscan_ver}"
PDB="$RPM_BUILD_DIR/%{name}-%{samba_ver}/examples/pdb"
dirs="$PDB $SAM $VFS"
(for i in $dirs; do make -C $i clean; done)
%if %{make_vscan}
(for i in %{vscan_modules}; do make -C $VSCAN/$i clean; done)
%endif
# install python
%if %{make_python}
cp -a source/build/lib.*/samba 			$RPM_BUILD_ROOT/usr/lib/%{python_ver}/lib-dynload/
find source/python -name CVS -print | xargs rm -rf
find source/python -name ".cvsignore" -print | xargs rm -rf
%endif
# whats this ?
install -m0755 source/bin/debug2html		$RPM_BUILD_ROOT/usr/bin/
# install smbwrapper
%if %{make_smbwrap}
install -m0755 source/bin/smbwrapper.so		$RPM_BUILD_ROOT/%{_libdir}/samba/
install -m0755 source/bin/smbsh		        $RPM_BUILD_ROOT/usr/bin/
%endif
##############
# cleanup docs
##############
#chmod 644 `find docs examples -type f`
#chmod 755 `find docs examples -type d`
#find . -name CVS -print | xargs rm -rf
#find . -name ".cvsignore" -print | xargs rm -rf
mv COPYING Manifest README Read-Manifest-Now Roadmap WHATSNEW.txt $RPM_BUILD_ROOT/%{DOCDIR}/
cp source/msdfs/README 		$RPM_BUILD_ROOT/%{DOCDIR}/README.msdfs
cp source/smbwrapper/README 	$RPM_BUILD_ROOT/%{DOCDIR}/README.smbwrapper
%if %{ul_version} >= 1
        SUFFIX="UnitedLinux"
%else
        SUFFIX="SuSE"
%endif
cp README.vendor		${RPM_BUILD_ROOT}/%{DOCDIR}/README.${SUFFIX}
# pam_smbpass is missing
cp -a source/pam_smbpass/samples 	examples/pam_smbpass/
cp -a source/pam_smbpass/{CHANGELOG,INSTALL,README,TODO} examples/pam_smbpass/
# prepare docbook package
cp -a docs/docbook/* 		$RPM_BUILD_ROOT/%{DOCBOOKDIR}
#make -C $RPM_BUILD_ROOT/%{DOCBOOKDIR} clean
rm -rf $RPM_BUILD_ROOT/%{DOCBOOKDIR}/autom4te.cache 
rm -rf $RPM_BUILD_ROOT/%{DOCBOOKDIR}/config.*
# this is empty
rm -rf docs/yodldocs
rm -rf examples/VFS/samba-vscan-%{vscan_ver}
# zip manpages at least
gzip -f docs/manpages/*.[1-9]
cp -a docs/*			$RPM_BUILD_ROOT/%{DOCDIR}
cp -a examples/			$RPM_BUILD_ROOT/%{DOCDIR}
# save space...
rm -r $RPM_BUILD_ROOT/%{SWATDIR}/using_samba 
ln -s %{DOCDIR}/htmldocs/using_samba $RPM_BUILD_ROOT/%{SWATDIR}
# hm...
cp $RPM_BUILD_ROOT/%{SWATDIR}/help/welcome.html $RPM_BUILD_ROOT/%{DOCDIR}/htmldocs/
rm -r $RPM_BUILD_ROOT/%{SWATDIR}/help
ln -s %{DOCDIR}/htmldocs $RPM_BUILD_ROOT/%{SWATDIR}/help
# remove cvs
find $RPM_BUILD_ROOT/%{DOCDIR} -name CVS -print | xargs rm -rf
find $RPM_BUILD_ROOT/%{DOCDIR} -name ".cvsignore" -print | xargs rm -rf
# finally build a file-list
for file in $( find ${RPM_BUILD_ROOT}%{DOCDIR} -maxdepth 1); do
        # exclude %{DOCDIR} and docbook
        case "${file#${RPM_BUILD_ROOT}}" in
                %{DOCDIR}|%{DOCDIR}/docbook) continue ;;
        esac
        echo "%doc ${file#${RPM_BUILD_ROOT}}" >> ${RPM_BUILD_DIR}/%{name}-%{samba_ver}/filelist-doc
done

%post
%{fillup_and_insserv smb}
mkdir -p $RPM_BUILD_ROOT/var/adm/notify/messages
cat << EOF > var/adm/notify/messages/samba-notify
Achtung!
This is %{name}-%{samba_ver}. Please do not run on production systems.
You have been warned.
EOF

%post client
%{fillup_and_insserv -fpy smbfs}
%{fillup_only -ans samba client}

%post winbind
%{fillup_and_insserv winbind}

%postun
%{insserv_cleanup}

%postun client
%{insserv_cleanup}

%postun winbind
%{insserv_cleanup}

%clean
#make -C source realclean

%files
#/usr/bin/addtosmbpass
#/usr/bin/convert_smbpasswd
%dir /etc/samba
%dir /usr/lib/samba
%config /etc/init.d/nmb
%config /etc/init.d/smb
%config /etc/pam.d/samba
%config(noreplace) /etc/samba/smbpasswd
%config(noreplace) /etc/samba/smbusers
%doc %{_mandir}/man1/smbcontrol.1.gz
%doc %{_mandir}/man1/smbstatus.1.gz
%doc %{_mandir}/man1/testparm.1.gz
%doc %{_mandir}/man1/testprns.1.gz
%doc %{_mandir}/man5/smbpasswd.5.gz
%doc %{_mandir}/man7/samba.7.gz
%doc %{_mandir}/man8/nmbd.8.gz
%doc %{_mandir}/man8/pdbedit.8.gz
%doc %{_mandir}/man8/smbd.8.gz
%doc %{_mandir}/man8/smbpasswd.8.gz
%doc %{_mandir}/man8/swat.8.gz
%doc %{_mandir}/man8/tdbbackup.8.gz
%{_includedir}/samba
/lib/security/pam_smbpass.so
/usr/bin/pdbedit
/usr/bin/smbcontrol
/usr/bin/smbpasswd
/usr/bin/smbstatus
/usr/bin/tdbbackup
/usr/bin/tdbdump  
/usr/bin/tdbtest  
/usr/bin/tdbtool  
/usr/bin/testparm
/usr/bin/testprns
/usr/lib/samba/rpc
/usr/lib/samba/vfs
/usr/sbin/nmbd
/usr/sbin/rcnmb
/usr/sbin/rcsmb
/usr/sbin/smbd
/usr/sbin/swat
/usr/share/samba
/var/lib/samba
/var/log/samba
/var/run/samba
/var/spool/samba

%files client
%config /etc/init.d/smbfs
%config(noreplace) /etc/samba/lmhosts
%config(noreplace) /etc/samba/smb.conf
%config(noreplace) /etc/samba/smbfstab
%dir /etc/samba
%dir /usr/lib/samba
%doc %{_mandir}/man1/editreg.1.gz
%doc %{_mandir}/man1/findsmb.1.gz
%doc %{_mandir}/man1/nmblookup.1.gz
%doc %{_mandir}/man1/profiles.1.gz
%doc %{_mandir}/man1/rpcclient.1.gz
%doc %{_mandir}/man1/smbcacls.1.gz
%doc %{_mandir}/man1/smbclient.1.gz
%doc %{_mandir}/man1/smbcquotas.1.gz
%doc %{_mandir}/man1/smbtar.1.gz
%doc %{_mandir}/man1/smbtree.1.gz
%doc %{_mandir}/man5/lmhosts.5.gz
%doc %{_mandir}/man5/smb.conf.5.gz
%doc %{_mandir}/man7/Samba.7.gz
%doc %{_mandir}/man8/net.8.gz
%doc %{_mandir}/man8/smbmnt.8.gz
%doc %{_mandir}/man8/smbmount.8.gz
%doc %{_mandir}/man8/smbspool.8.gz
%doc %{_mandir}/man8/smbumount.8.gz
/sbin/mount.smbfs
/usr/bin/editreg
/usr/bin/findsmb
/usr/bin/net
/usr/bin/nmblookup
/usr/bin/profiles
/usr/bin/rpcclient
/usr/bin/smbcacls
/usr/bin/smbclient
/usr/bin/smbcquotas
/usr/bin/smbfilter
/usr/bin/smbmnt
/usr/bin/smbmount
/usr/bin/smbspool
/usr/bin/smbtar
/usr/bin/smbtree
/usr/bin/smbumount
/usr/lib/samba/lowcase.dat
/usr/lib/samba/upcase.dat
/usr/lib/samba/valid.dat
/usr/sbin/rcsmbfs
%if %{make_smbwrap}
/usr/bin/smbsh
%doc %{_mandir}/man1/smbsh.1.gz
/usr/lib/samba/smbwrapper.so
%endif

%files winbind
%config /etc/init.d/winbind
%config(noreplace) /etc/samba/smb.conf
%dir /etc/samba
%doc %{_mandir}/man1/wbinfo.1.gz
%doc %{_mandir}/man8/winbindd.8.gz
%doc %{_mandir}/man1/ntlm_auth.1.gz
/lib/libnss_winbind.so*
/lib/libnss_wins.so*
/lib/security/pam_winbind.so
/usr/bin/ntlm_auth
/usr/bin/wbinfo
/usr/sbin/rcwinbind
/usr/sbin/winbindd

%files utils
%doc %{_mandir}/man1/vfstest.1.gz
/usr/bin/debug2html
/usr/bin/locktest
/usr/bin/locktest2
/usr/bin/masktest
/usr/bin/msgtest
/usr/bin/nsstest
/usr/bin/smbtorture
/usr/bin/talloctort
/usr/bin/tdbtorture
/usr/bin/vfstest

%files doc -f filelist-doc
%dir /usr/share/doc/packages/samba3

%files docbook
%docdir %{DOCBOOKDIR}
%{DOCBOOKDIR}
%dir /usr/share/doc/packages/samba3

%files pdb
/usr/lib/samba/pdb
%doc examples/pdb/{Makefile,README,pdb_test.c}
%doc examples/pdb/{mysql/mysql.dump,mysql/smb.conf}
%if %{make_cifsvfs}

%files cifsmount
/sbin/mount.cifs
%endif
%if %{make_wrepld}

%files wrepld
%config /etc/init.d/wrepl
/usr/sbin/rcwrepl
/usr/sbin/wrepld
%endif
%if %{make_vscan}

%files vscan
/usr/lib/samba/vscan
%doc samba-vscan-%{vscan_ver}/{AUTHORS,COPYING,ChangeLog,FAQ,NEWS,README,TODO}
%endif
%if %{make_python}

%files python
%doc source/python/README 
%doc source/python/examples 
%doc source/python/gprinterdata
%doc source/python/gtdbtool
%doc source/python/gtkdictbrowser.py
/usr/lib/%{python_ver}/lib-dynload/samba
%endif

%files -n libsmbclient
%{_libdir}/libsmbclient.so.*

%files -n libsmbclient-devel
%{_includedir}/libsmbclient.h
%{_libdir}/libsmbclient.a
%{_libdir}/libsmbclient.so

%description
samba3


%description client
samba3-client


%description winbind
samba3-winbind


%description utils
samba3-utils


%description doc
samba3-doc


%description docbook
samba3-docbook


%description pdb
samba3-pdb

%if %{make_cifsvfs}

%description cifsmount
samba3-cifsmount

%endif
%if %{make_vscan}

%description vscan
samba3-vscan

%endif
%if %{make_python}

%description python
samba3-python

%endif
%if %{make_wrepld}

%description wrepld
samba3-wrepld

%endif

%description -n libsmbclient
This package includes the libsmbclient library.

Authors:
--------
    The Samba Team <samba@samba.org>


%description -n libsmbclient-devel
This package contains static libraries and header files needed to develop
programs which make use of the smbclient programming interface.

Authors:
--------
    The Samba Team <samba@samba.org>


