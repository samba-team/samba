#
# spec file for package samba (Version 2.2.3a.200204230937cvs)
#
# Copyright (c) 2002 SuSE Linux AG, Nuernberg, Germany.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
# please send bugfixes or comments to feedback@suse.de.
#

# neededforbuild  automake cups-devel cups-libs cyrus-sasl cyrus-sasl-devel cyrus-sasl-gssapi des openldap2 openldap2-client openldap2-devel openssl openssl-devel popt readline readline-devel
# usedforbuild    aaa_base aaa_dir aaa_version autoconf automake base bash bindutil binutils bison bzip compat cpio cpp cracklib cups-devel cups-libs cyrus-sasl cyrus-sasl-devel cyrus-sasl-gssapi db des devs diffutils e2fsprogs file fileutils findutils flex gawk gcc gdbm gdbm-devel gettext glibc glibc-devel glibc-locale gpm grep groff gzip heimdal-lib kbd less libgcc libstdc++ libtool libxcrypt libz m4 make man mktemp modutils ncurses ncurses-devel net-tools netcfg openldap2 openldap2-client openldap2-devel openssl openssl-devel pam pam-devel pam-modules patch perl popt ps rcs readline readline-devel rpm sendmail sh-utils shadow strace syslogd sysvinit texinfo textutils timezone unzip util-linux vim

Name:         samba
Version:      PVERSION
Release:      PRELEASE
License:      1992-95 Andrew Tridgell, Karl Auer, Jeremy Allison
Group:        Productivity/Networking/Samba
Url:          http://www.samba.org
Provides:     smbfs
Autoreqprov:  on
Requires:     samba-client = %{version}
Summary:      An SMB file server for Unix
Source:       ftp://ftp.samba.org/pub/samba/%{name}-%{version}.tar.bz2
Source1:      samba.pamd
Source10:     lmhosts
Source13:     rc.smb
Source14:     rc.smbfs
Source15:     smb.conf
Source16:     smbpasswd
Source17:     smbusers
#Patch:		samba-%{version}.dif
Patch:        samba-2.2.4.dif
Patch1:       samba-2.2.4-pid_path.diff
Patch2:       samba-2.2.4-vfs_modules.diff
Patch3:       samba-2.2.3-smbadduser.dif
Patch4:       samba-2.2.3-smbsh.dif
BuildRoot:    %{_tmppath}/%{name}-%{version}-build
%define		ETCSMBDIR	/%{_sysconfdir}/samba
%define		LIBDIR		%{_libdir}/samba
%define		DOCDIR		%{_defaultdocdir}/%{name}
%define		SHAREDIR	%{_datadir}/samba
%define		CODEPAGEDIR	%{SHAREDIR}/codepages
%define		SWATDIR		%{SHAREDIR}/swat
%define		LOCKDIR		/%{_localstatedir}/lib/samba
%define		LOGDIR		/%{_localstatedir}/log/samba
%define		PIDDIR		/%{_localstatedir}/run/samba
%define		INITDIR 	%(if [ -x /sbin/insserv ]; then echo -n etc ; else echo -n sbin; fi)/init.d

%description
Samba is a suite of programs which work together to allow clients to access Unix filespace and printers via the SMB protocol (Server Message Block).

In practice, this means that you can redirect disks and printers to
Unix disks and printers from LAN Manager clients, Windows for
Workgroups 3.11 clients, Windows'95 clients, Windows NT clients
and OS/2 clients. There is also a Unix client program supplied as part of the suite which allows Unix users to use an ftp-like interface to access filespace and printers on any other SMB server.

Samba includes the following programs (in summary):

* smbd, the SMB server. This handles actual connections from clients.

* nmbd, the Netbios name server, which helps clients locate servers.

* smbclient, the Unix-hosted client program.

* smbrun, a little 'glue' program to help the server run external programs.

* testprns, a program to test server access to printers.

* testparm, a program to test the Samba configuration file for correctness.

* smb.conf, the Samba configuration file.

* smbprint, a sample script to allow a Unix host to use smbclient
  to print to an SMB server.

The suite is supplied with full source and is GPLed.

This package expects its config file under /etc/samba/smb.conf.

Authors:
--------
    Andrew Tridgell <Andrew.Tridgell@anu.edu.au>
    Karl Auer <Karl.Auer@anu.edu.au>
    Jeremy Allison <jeremy@netcom.com>

SuSE series: n

%package client
Summary:      Samba client utilities
Autoreqprov:  on
Group:        Productivity/Networking/Samba
Provides:     smbclnt
Obsoletes:    smbclnt

%description client
This package contains all programs, that are needed to act as a samba
client. This includes also smbmount, of course.

Authors:
--------
    Andrew Tridgell <Andrew.Tridgell@anu.edu.au>
    Karl Auer <Karl.Auer@anu.edu.au>
    Jeremy Allison <jeremy@netcom.com>

SuSE series: n

%prep
%setup
%patch
%patch1
%patch2
%patch3
%patch4
echo %{version} | grep cvs &&
	echo "#define VERSION \"%{version}\"" > source/include/version.h

%build
cd source
%{?suse_update_config:%{suse_update_config -f}}
autoconf
# -O Means: Don't do inlining(cancels O2 from OPT_FLAGS), bins are big enough
CFLAGS="$RPM_OPT_FLAGS -Wall -O -D_GNU_SOURCE -D_LARGEFILE64_SOURCE" \
./configure \
	--prefix=%{_prefix} \
	--libdir=%{LIBDIR} \
	--localstatedir=%{LOCKDIR} \
	--mandir=%{_mandir} \
	--sbindir=%{_sbindir} \
	--with-codepagedir=%{CODEPAGEDIR} \
	--with-privatedir=%{ETCSMBDIR} \
	--with-configdir=%{ETCSMBDIR} \
	--with-swatdir=%{SWATDIR} \
	--with-sambabook=%{DOCDIR}/htmldocs/using_samba \
	--with-lockdir=%{LOCKDIR} \
	--with-automount \
	--with-smbmount \
	--with-smbwrapper \
	--with-pam \
	--with-pam_smbpass \
	--with-syslog \
	--with-profiling-data \
	--with-quotas \
	--with-utmp \
	--with-msdfs \
	--with-vfs \
	--with-libsmbclient \
	--with-acl-support \
	--with-winbind
make \
	LOGFILEBASE=%{LOGDIR} \
	PASSWDPROG=/%{_bindir}/passwd \
	PIDDIR=%{PIDDIR}
make	nsswitch
make	nsswitch/libnss_wins.so
make -C ../examples/VFS
make -C ../examples/VFS/block

%install
[ "$RPM_BUILD_ROOT" != "/" ] && [ -d $RPM_BUILD_ROOT ] && rm -rf $RPM_BUILD_ROOT
cd source/
mkdir -p \
	$RPM_BUILD_ROOT/%{_bindir} \
	$RPM_BUILD_ROOT/sbin \
	$RPM_BUILD_ROOT/%{_sbindir} \
	$RPM_BUILD_ROOT/%{ETCSMBDIR} \
	$RPM_BUILD_ROOT/%{INITDIR} \
	$RPM_BUILD_ROOT/%{LIBDIR} \
	$RPM_BUILD_ROOT/%{_includedir} \
	$RPM_BUILD_ROOT/%{_lib}/security \
	$RPM_BUILD_ROOT/%{_mandir} \
	$RPM_BUILD_ROOT/%{CODEPAGEDIR} \
	$RPM_BUILD_ROOT/%{SHAREDIR}/script \
	$RPM_BUILD_ROOT/%{DOCDIR} \
	$RPM_BUILD_ROOT/%{LOCKDIR} \
	$RPM_BUILD_ROOT/%{SWATDIR} \
	$RPM_BUILD_ROOT/%{LOGDIR} \
	$RPM_BUILD_ROOT/%{PIDDIR} \
	$RPM_BUILD_ROOT/%{_localstatedir}/spool/samba
	
make \
	BASEDIR=$RPM_BUILD_ROOT/%{_prefix} \
	BINDIR=$RPM_BUILD_ROOT/%{_bindir} \
	SBINDIR=$RPM_BUILD_ROOT/%{_sbindir} \
	LIBDIR=$RPM_BUILD_ROOT/%{LIBDIR} \
	MANDIR=$RPM_BUILD_ROOT/%{_mandir} \
	CODEPAGEDIR=$RPM_BUILD_ROOT/%{CODEPAGEDIR} \
	LOCKDIR=$RPM_BUILD_ROOT/%{LOCKDIR} \
	SWATDIR=$RPM_BUILD_ROOT/%{SWATDIR} \
	install
# smbadduser
install -m 755 script/smbadduser $RPM_BUILD_ROOT/%{_bindir}/smbadduser
# call smbmount as mount.smbfs
ln -sf %{_bindir}/smbmount $RPM_BUILD_ROOT/sbin/mount.smbfs
# smbpass pam support
install -m 755 bin/pam_smbpass.so $RPM_BUILD_ROOT/%{_lib}/security
# wins support for NSS
install -m 755 nsswitch/libnss_wins.so $RPM_BUILD_ROOT/%{_lib}/libnss_wins.so.2
# winbind and shared libraries
install -m 755 nsswitch/libnss_winbind.so $RPM_BUILD_ROOT/%{_lib}/libnss_winbind.so.2
install -m 755 nsswitch/pam_winbind.so $RPM_BUILD_ROOT/%{_lib}/security
# libsmbclient
install -m 644 include/libsmbclient.h $RPM_BUILD_ROOT/%{_includedir}
install -m 644 bin/libsmbclient.a $RPM_BUILD_ROOT/%{_libdir}
install -m 755 bin/libsmbclient.so $RPM_BUILD_ROOT/%{_libdir}
# smbwrapper lib
install -m 755 bin/smbwrapper.so $RPM_BUILD_ROOT/%{_libdir}/samba
# doc
mv msdfs/README $RPM_BUILD_ROOT/%{DOCDIR}/README.msdfs
mv nsswitch/README $RPM_BUILD_ROOT/%{DOCDIR}/README.nsswitch
mv smbwrapper/README $RPM_BUILD_ROOT/%{DOCDIR}/README.smbwrapper
mkdir $RPM_BUILD_ROOT/%{DOCDIR}/pam_smbpass
mv pam_smbpass/README $RPM_BUILD_ROOT/%{DOCDIR}/pam_smbpass
mv pam_smbpass/samples $RPM_BUILD_ROOT/%{DOCDIR}/pam_smbpass
# utility scripts
cd script
install -m 755 convert_smbpasswd $RPM_BUILD_ROOT/%{SHAREDIR}/script
install -m 755 mknissmbp* $RPM_BUILD_ROOT/%{SHAREDIR}/script
install -m 755 mksmbpasswd.sh $RPM_BUILD_ROOT/%{SHAREDIR}/script
cd ../..
# findsmb
install -m 755 packaging/RedHat/findsmb $RPM_BUILD_ROOT/%{_bindir}/findsmb
# VFS libs
for module in $( find examples/VFS/ -name *.so); do
	install -m 755 "${module}" $RPM_BUILD_ROOT/%{LIBDIR}/
	rm "${module}"
done
# Remove superfluous files
for fn in Makefile *.c *.o .libs; do
	find examples/VFS/ -iname $fn -print0 | xargs -0 rm -rf
done
# Cleanup docs
rm -rf \
	docs/{docbook,manpages,yodldocs} \
	docs/faq/*{sgml,txt} \
	docs/htmldocs/*.[0-9].html \
	$RPM_BUILD_ROOT/%{SWATDIR}/using_samba
find docs examples -type d -print0 | xargs -0 chmod 755
find docs examples -type f -print0 | xargs -0 chmod 644
# doc
mv docs/* examples COPYING Manifest README Roadmap WHATSNEW.txt $RPM_BUILD_ROOT/%{DOCDIR}

# configuration files
install -m 644 $RPM_SOURCE_DIR/smb.conf $RPM_BUILD_ROOT/%{ETCSMBDIR}/
install -m 644 $RPM_SOURCE_DIR/lmhosts $RPM_BUILD_ROOT/%{ETCSMBDIR}/
install -m 600 $RPM_SOURCE_DIR/smbpasswd $RPM_BUILD_ROOT/%{ETCSMBDIR}/
install -m 644 $RPM_SOURCE_DIR/smbusers $RPM_BUILD_ROOT/%{ETCSMBDIR}/
install -D -m 644 $RPM_SOURCE_DIR/samba.pamd $RPM_BUILD_ROOT/%{_sysconfdir}/pam.d/samba
# start script
install -m 744 $RPM_SOURCE_DIR/rc.smb $RPM_BUILD_ROOT/%{INITDIR}/smb
ln -sf ../../%{INITDIR}/smb $RPM_BUILD_ROOT/%{_sbindir}/rcsmb
ln -sf ../../%{INITDIR}/smb $RPM_BUILD_ROOT/%{_sbindir}/rcsamba
install -m 744 $RPM_SOURCE_DIR/rc.smbfs $RPM_BUILD_ROOT/%{INITDIR}/smbfs
ln -sf ../../%{INITDIR}/smbfs $RPM_BUILD_ROOT/%{_sbindir}/rcsmbfs
# create netlogon and profiles directories
mkdir -p $RPM_BUILD_ROOT/%{_localstatedir}/lib/samba/{netlogon,profiles}
# let ldconfig create symlinks
ldconfig -n $RPM_BUILD_ROOT/%{_libdir}

%post
# Are we in update mode?
if [ $1 -gt 1 ]; then
	rm -f $( find tmp/.*.EtCmV -size 0 2> /dev/null)
	for fn in lmhosts smb.conf smbpasswd; do
		if [ -e etc/$fn -a ! -L etc/$fn ]; then
			if [ ! -e tmp/.samba.EtCmV ]; then
				echo "Copying samba config files to new location /etc/samba/:"
				touch tmp/.samba.EtCmV
			fi
		  	echo $fn
			if [ -f etc/samba/$fn ]; then
				diff etc/$fn etc/samba/$fn >/dev/null ||
					mv etc/samba/$fn etc/samba/$fn.rpmpost
			fi
			cp -a etc/$fn etc/samba/$fn
			touch tmp/.$fn.EtCmV
		fi
	done
	rm -f $( find tmp/.samba.EtCmV -size 0 2> /dev/null)
	for fn in $( find etc/*.SID 2> /dev/null) secrets.tdb; do
	  	fn=$( basename $fn)
		if [ -e etc/$fn -a ! -L etc/$fn -a ! -e etc/samba/$fn ]; then
				if [ ! -e tmp/.samba.EtCmV ]; then
					echo "Copying samba SID and secret files to new location /etc/samba/:"
					touch tmp/.samba.EtCmV
				fi
		  	echo $fn
			cp -a etc/$fn etc/samba/$fn
		fi
	done
	rm -f $( find tmp/.samba.EtCmV -size 0 2> /dev/null)
fi
mkdir -p var/adm/notify/messages
cat << EOF > var/adm/notify/messages/samba-notify
Hallo,	(english text below)
 
die Konfigurationsdateien, lmhosts, smb.conf und smbpasswd, liegen jetzt
in /etc/samba. Bei einem Update wird die alte Konfiguration dorthin
kopiert. Insoweit die Dateien angepasst wurden, finden sich in /etc
Sicherungskopien mit der Endung .rpmsave. Die mitgelieferten neuen
Beispieldateien werden gegebenenfalls mit der Endung .rpmpost oder
.rpmnew gesichert.
 
 
Hello,
 
the configuration files, lmhosts, smb.conf und smbpasswd, are now
located in /etc/samba. While an update the old configuration will be
copied here. If you made changes to these files, also backups with
endings .rpmsave are left in /etc. The new example configuration files
are stored with the ending .rpmpost or .rpmnew if necessary.
 
Have a lot of fun...
			Your SuSE Team
EOF
# ---------------------------------------------------------------------------
#
# Initialize runlevel links and take care of old START_SMB
#
%{fillup_and_insserv smb}

%postun
%{insserv_cleanup}

%post client
# check and copy old or old.rpmsave configuration files
function ckandcp()
{
	if [ ! -e tmp/.samba-client.EtCmV ]; then
		echo "Copying samba-client config files to new location /etc/samba/:"
		touch tmp/.samba-client.EtCmV
	fi
  	echo "$fn"
	if [ -f etc/samba/$fn ]; then
		diff etc/$1 etc/samba/$fn >/dev/null ||
			mv etc/samba/$fn etc/samba/$fn.rpmpost
	fi
	cp -a etc/$1 etc/samba/$fn
}
for fn in lmhosts smb.conf; do
	if [ -e etc/$fn -a ! -L etc/$fn ]; then
		ckandcp $fn
	elif [ -e tmp/.$fn.EtCmV -a -e etc/$fn.rpmsave -a ! -L etc/$fn.rpmsave ]; then
		ckandcp $fn.rpmsave
	fi
done
rm -f $( find tmp/.*.EtCmV -size 0 2> /dev/null)
# never had a start-variable, no fillup magic needed
%{fillup_and_insserv -fpy smbfs}

%postun client
%{insserv_cleanup}

%files
%config /%{_sysconfdir}/pam.d/samba
%config /%{_sysconfdir}/init.d/smb
%config(noreplace) /%{ETCSMBDIR}/smbpasswd
%config(noreplace) /%{ETCSMBDIR}/smbusers
%{_bindir}/make_printerdef
%{_bindir}/make_smbcodepage
%{_bindir}/make_unicodemap
# build without --ldapsam
#%{_bindir}/pdbedit
%{_bindir}/smbadduser
%{_bindir}/smbstatus
%{_bindir}/tdbbackup
%{_bindir}/testprns
%{_sbindir}/nmbd
%{_sbindir}/rcsmb
%{_sbindir}/rcsamba
%{_sbindir}/smbd
%{_sbindir}/swat
/%{_lib}/security/pam_smbpass.so
%{LIBDIR}
%dir %{SHAREDIR}
%{SHAREDIR}/script
%{SWATDIR}
%doc %{_mandir}/man1/make_smbcodepage.1.gz
%doc %{_mandir}/man1/make_unicodemap.1.gz
%doc %{_mandir}/man1/smbsh.1.gz
%doc %{_mandir}/man1/smbstatus.1.gz
%doc %{_mandir}/man1/testprns.1.gz
%doc %{_mandir}/man5/smbpasswd.5.gz
%doc %{_mandir}/man7/samba.7.gz
%doc %{_mandir}/man8/nmbd.8.gz
%doc %{_mandir}/man8/smbd.8.gz
%doc %{_mandir}/man8/swat.8.gz
%dir /%{_localstatedir}/lib/samba/netlogon
%attr(770,root,users) %dir /%{_localstatedir}/lib/samba/profiles
%attr(750,lp,lp) %dir /%{_localstatedir}/spool/samba
%dir %{LOCKDIR}
%attr(750,root,root) %dir %{LOGDIR}
%dir %{PIDDIR}

%files client
%dir %{ETCSMBDIR}
%config(noreplace) /%{ETCSMBDIR}/smb.conf
%config(noreplace) /%{ETCSMBDIR}/lmhosts
%config /%{_sysconfdir}/init.d/smbfs
%{_bindir}/findsmb
%{_bindir}/nmblookup
%{_bindir}/rpcclient
%{_bindir}/smbcacls
%{_bindir}/smbclient
%{_bindir}/smbcontrol
%{_bindir}/smbmnt
%{_bindir}/smbmount
%{_bindir}/smbpasswd
%{_bindir}/smbsh
%{_bindir}/smbumount
%{_bindir}/smbspool
%{_bindir}/smbtar
%{_bindir}/testparm
%{_bindir}/wbinfo
%{_sbindir}/rcsmbfs
%{_sbindir}/winbindd
/sbin/mount.smbfs
%{CODEPAGEDIR}
/%{_lib}/libnss_wins.so.2
/%{_lib}/libnss_winbind.so.2
/%{_lib}/security/pam_winbind.so
%{_includedir}/libsmbclient.h
%{_libdir}/libsmbclient.a
%{_libdir}/libsmbclient.so
%{_libdir}/libsmbclient.so.0
%{_libdir}/samba/smbwrapper.so
%doc %{_mandir}/man1/findsmb.1.gz
%doc %{_mandir}/man1/nmblookup.1.gz
%doc %{_mandir}/man1/rpcclient.1.gz
%doc %{_mandir}/man1/smbcacls.1.gz
%doc %{_mandir}/man1/smbclient.1.gz
%doc %{_mandir}/man1/smbcontrol.1.gz
%doc %{_mandir}/man1/testparm.1.gz
%doc %{_mandir}/man1/wbinfo.1.gz
%doc %{_mandir}/man1/smbtar.1.gz
%doc %{_mandir}/man5/lmhosts.5.gz
%doc %{_mandir}/man5/smb.conf.5.gz
%doc %{_mandir}/man8/smbmnt.8.gz
%doc %{_mandir}/man8/smbmount.8.gz
%doc %{_mandir}/man8/smbpasswd.8.gz
%doc %{_mandir}/man8/smbspool.8.gz
%doc %{_mandir}/man8/smbumount.8.gz
%doc %{_mandir}/man8/winbindd.8.gz
%docdir %{DOCDIR}
%{DOCDIR}

%changelog -n samba
* Fri Mar 08 2002 - kukuk@suse.de
- Add libsmbclient.so.0 and /usr/share/samba to filelist
* Thu Feb 14 2002 - adrian@suse.de
- install needed header file for libsmbclient.so
* Sun Feb 10 2002 - kukuk@suse.de
- Don't test for -fpic if PICFLAG is already set
* Thu Feb 07 2002 - lmuelle@suse.de
- Update to 2.2.3a, minor bugfix release
* Thu Feb 07 2002 - lmuelle@suse.de
- Update to 2.2.3
- Fix smbsh library search path
- Removed 'kernel oplocks = No' from smb.conf; default is yes
- Include pam_smbpass, syslog, utmp, and winbind support
- Include libsmbclient
- Include findsmb
* Tue Jan 08 2002 - egmont@suselinux.hu
- Cosmetical changes in init scripts
* Thu Dec 20 2001 - ro@suse.de
- removed START_SMB and added insserv_macros
* Sun Sep 23 2001 - lmuelle@suse.de
- Shorten output and tunig of old configuration files handling
- Include SID and secrets files to old configuration files handling
- Move netlogon and profiles directories to /var/lib/samba
- Move smbpasswd binary and man page to samba-client package
- Introduce additional sym link from /etc/init.d/smb to rcsamba due to
  too many typos and cleaner systematic
- Add character set = ISO8859-15 and client code page = 850 to smb.conf
  in the global section to enable correct UNIX <-> DOS character
  mapping for west European languages
- Change create mask of home section to 0640, directory mask to 0750;
  change create mask of printers section to 0600 in smb.conf
- Move path of printers section to /var/tmp
* Fri Aug 24 2001 - lmuelle@suse.de
- Move all configuration files to /etc/samba
- Move data bases to /var/lib/samba; important, cause boot script
  cleans up /var/lock/samba
- Move pid files to /var/run/samba
- Link against cups library
- Use build root
- Rename subpackage smbclnt to samba-client
- Move /usr/share/doc/packages/samba to package samba-client
- Move /usr/lib/samba/scripts to /usr/share/samba/scripts
- Move /usr/lib/samba/codepages to /usr/share/samba/codepages
- Move /usr/lib/samba/swat to /usr/share/samba/swat
- Move /usr/lib/samba/VFS/* to /usr/lib/samba
- Remove smb.conf from package samba, kept in samba-client
- Remove redundant html documentation of man pages
- Remove superfluous install and uninstall scripts
- Add example configuration file /etc/samba/smbusers
- Update to 2.2.1a: fixes bug with too strict name handling while adding
  a machine into a domain
- Update to 2.2.1: add pam password changing and pam restrictions code;
  printer driver management improvements (delete driver); fix for Samba
  running on top of Linux VFAT ftruncate bug
* Tue Aug 14 2001 - ro@suse.de
- Don't use absolute paths to PAM modules in PAM config files
* Wed Jun 27 2001 - ro@suse.de
- re-added the libtoolize to make it build
* Tue Jun 26 2001 - lmuelle@suse.de
- Update to 2.2.0a fixes remote file create/ append bug. This may
  only happen by '%%m' macro usage for the 'log file' command.
- spec and dif cleanup
- Include VFS module support.
* Wed Jun 13 2001 - ro@suse.de
- fix to build with new autoconf
* Wed May 30 2001 - ro@suse.de
- config-dist.sh: accept any kernel version on s390
* Thu May 10 2001 - bodammer@suse.de
- initscript fix: don't start smbd in runlevel 2 [bug #8046]
- some additional files included to doc (COPYING, README, ..)
* Wed May 09 2001 - uli@suse.de
- bzipped tarball
* Tue May 08 2001 - schwab@suse.de
- Don't use _syscallX.
* Mon Apr 30 2001 - ro@suse.de
- added config-dist.sh to build only on 2.4 machines
  (samba configure seems braindead enough to check
  the running kernel)
* Mon Apr 30 2001 - ro@suse.de
- removed kerberos support: does not work as expected
* Tue Apr 24 2001 - lemsi@suse.de
- for 7.2 we have added some kerbereos 5 support
* Tue Apr 24 2001 - lemsi@suse.de
- new version samba 2.2
- new spec file with more functions for configure
- libnss_winbind.so support for /etc/nsswich.conf
* Wed Apr 18 2001 - lemsi@suse.de
- new security fixes and version 2.0.8 for 6.3, 6.4, 7.0, 7.1
* Tue Apr 17 2001 - lemsi@suse.de
- new rcsmb script
- include security fixes
* Fri Mar 09 2001 - ro@suse.de
- don't mess with os_install_post
* Fri Feb 23 2001 - ro@suse.de
- added readline/readline-devel to neededforbuild (split from bash)
* Wed Feb 07 2001 - schwab@suse.de
- Fix LFS support in client.
* Mon Feb 05 2001 - schwab@suse.de
- Compile with -D_GNU_SOURCE and -D_LARGEFILE64_SOURCE to get missing
  declarations.
- Include <sys/types.h> when checking for ino64_t.
- Include <crypt.h> for crypt declaration.
* Wed Jan 31 2001 - lemsi@suse.de
- added codepages in smbclnt-subpackage
- changed german coments to english coments
* Wed Jan 03 2001 - lemsi@suse.de
- changed in the share section the path /cd to /cdrom
- added smb.conf to the smbclnt-subpackage
* Tue Nov 28 2000 - kukuk@suse.de
- Fix init scripts and move them to /etc/init.d
- Fix post/postun section for subpackages
* Fri Nov 24 2000 - bodammer@suse.de
- rcscript update
* Mon Aug 28 2000 - choeger@suse.de
- changed $* to "$@" in mount.smbfs to make it also
  possible to mount shares with spaces
* Mon Jul 31 2000 - choeger@suse.de
- improvement for rcsmb
- fix for spec-file to compile with NIS netgroups
* Thu Jul 20 2000 - choeger@suse.de
- added smbfs initscript that has been removed
  by an error
* Tue Jul 11 2000 - choeger@suse.de
- split package into client and server parts
  client package name: smbclnt
* Wed Apr 26 2000 - choeger@suse.de
- new version, 2.0.7
* Thu Apr 06 2000 - ro@suse.de
- removed pam,cracklib from neededforbuild: build handles this
* Wed Apr 05 2000 - bk@suse.de
- s390 team added config.{sub,guess} update macro for s390
* Mon Mar 27 2000 - choeger@suse.de
- fixed bug in specfile
  the multilined configure call missed a "\" :-(
* Thu Mar 09 2000 - choeger@suse.de
- fixed typo in specfile
* Wed Mar 01 2000 - choeger@suse.de
- added %%{_mandir}
* Tue Feb 08 2000 - choeger@suse.de
- removed /sbin/init.d/smbfs because it is no longer needed
* Mon Jan 03 2000 - choeger@suse.de
- bugfix for ipc.c
  to make roaming profiles work again.
* Tue Nov 30 1999 - choeger@suse.de
- changed kernel oplocks = off to
  kernel oplocks = false
* Tue Nov 16 1999 - choeger@suse.de
- added kernel oplocks = off in smb.conf
* Fri Nov 12 1999 - choeger@suse.de
- new version, 2.0.6
* Fri Nov 05 1999 - choeger@suse.de
- Fix for the smbmount lost-connection problem
  _seems_ to work...
* Fri Oct 29 1999 - choeger@suse.de
- removed comment sign in /etc/inetd.conf for swat
* Mon Sep 13 1999 - bs@suse.de
- ran old prepare_spec on spec file to switch to new prepare_spec.
* Tue Aug 10 1999 - fehr@suse.de
- set execute permissions for mksmbpasswd.sh and changesmbpasswd.sh
* Thu Jul 29 1999 - fehr@suse.de
- fixed typo in /sbin/init.d/smbfs
* Thu Jul 22 1999 - fehr@suse.de
- changed to new version 2.0.5a
* Wed Jul 21 1999 - fehr@suse.de
- changed to new version 2.0.5
* Tue Jul 20 1999 - fehr@suse.de
- install /sbin/init.d/smbfs
- changed to new version 2.0.5pre4
* Mon Jul 19 1999 - fehr@suse.de
- add /sbin/init.d/smbfs
- changed to new version 2.0.5pre3
* Fri Jul 02 1999 - fehr@suse.de
- removed "umount -a -t smbfs" from start sscript
* Tue Jun 22 1999 - kukuk@suse.de
- 2.0.4b changed default values, enable PAM again
* Fri Jun 18 1999 - kukuk@suse.de
- changed to new version 2.0.4b
* Mon Jun 14 1999 - kukuk@suse.de
- Enable PAM, add samba.pamd
* Mon May 03 1999 - fehr@suse.de
- add umount -a -t smbfs to shutdown sequence of samba
* Thu Mar 11 1999 - ro@suse.de
- smbmount: define NR_OPEN to 1024 if undefined (GLIBC-2.1)
* Wed Mar 10 1999 - choeger@suse.de
- some enhancements for smb.conf
* Wed Mar 10 1999 - choeger@suse.de
- new version 2.0.3 and smbmount now seems to work
* Tue Mar 09 1999 - ro@suse.de
- use samba-2.0.2 for STABLE
- use smbfs-2.1 with kernel 2.2.2
* Sun Feb 28 1999 - ro@suse.de
- for glibc-2.1 strncat uses strcat for one subcase, so don't
  redefine strcat to "ERROR" for glibc-2.1
* Mon Feb 15 1999 - fehr@suse.de
- fix for umount problem from Volker
* Tue Feb 09 1999 - fehr@suse.de
- changed to version 2.0.2 of samba
* Fri Jan 15 1999 - bs@suse.de
- replaced /sbin/init.d/smb with newer style version (again)
* Fri Jan 15 1999 - fehr@suse.de
- switched to new version 2.0.0
* Wed Jan 13 1999 - bs@suse.de
- fixed entry in inetd.conf
* Wed Jan 13 1999 - bs@suse.de
- replaced /sbin/init.d/smb with newer style version
* Mon Jan 11 1999 - vl@suse.de
- make 2.0.0beta5 package of samba
* Mon Aug 24 1998 - vl@suse.de
- changed to version 1.9.18p10
* Mon Jun 29 1998 - vl@suse.de
- changed to version 1.9.18p8
* Mon Apr 20 1998 - vl@suse.de
- changed to version 1.9.18p4
* Thu Feb 19 1998 - vl@suse.de
- changed to version 1.9.18p3
* Tue Feb 03 1998 - vl@suse.de
- changed to version 1.9.18p2
- fixed some problems in spec-file, some files were missing :-(
- fixed smbfs-2.0.2/Makefile.Linux
* Tue Jan 13 1998 - vl@suse.de
- changed to version 1.9.18p1
* Fri Jan 09 1998 - vl@suse.de
- changed to version 1.9.18
* Tue Dec 02 1997 - bs@suse.de
- disable samba by default in /etc/rc.config
* Mon Oct 06 1997 - fehr@suse.de
- package prepared for automatic building
* Mon Sep 29 1997 - fehr@suse.de
- updated to version 1.9.17p2 due to security hole.
* Wed Jul 16 1997 - fehr@suse.de
- add fillup-template for rc.config and install it in doinst.sh
* Fri Jun 27 1997 - bs@suse.de
- update to smbfs-2.0.2, due to security hole.
* Tue Jun 17 1997 - fehr@suse.de
- changed init-skript to recognize entry START_SMB of rc.config
* Mon Jun 02 1997 - vl@suse.de
- update to version 1.9.16p11
- Starting Samba from /sbin/init.d, not from inetd.conf
* Sun Feb 02 1997 - vl@suse.de
- update to version 1.9.16p10
- Adapted /etc/smb.conf.sample to 4.4.1 manual
* Thu Jan 02 1997 - florian@suse.de
- update to version 1.9.16p9
- configuration file is now /etc/smb.conf
- smbd and nmbd are now in /usr/sbin
- added start-script /sbin/init.d/smb and entry in /etc/rc.config
* Thu Jan 02 1997 - florian@suse.de
- Update auf neue Version 1.9.16p6.
