#
# spec file for package samba (Version 2.0.7)
# 
# Copyright  (c)  2000  SuSE GmbH  Nuernberg, Germany.
#
# please send bugfixes or comments to feedback@suse.de.
#

# neededforbuild  automake openldap
# usedforbuild    aaa_base aaa_dir autoconf automake base bash bindutil binutils bison bzip compress cpio cracklib devs diff ext2fs file fileutil find flex gawk gcc gdbm gettext gpm gppshare groff gzip kbd less libc libtool libz lx_suse make mktemp modules ncurses net_tool netcfg nkita nkitb nssv1 openldap pam patch perl pgp ps rcs rpm sendmail sh_utils shadow shlibs strace syslogd sysvinit texinfo textutil timezone unzip util vim xdevel xf86 xshared

Vendor:       SuSE GmbH, Nuernberg, Germany
Distribution: SuSE Linux 7.1a (i386)
Name:         samba
Release:      0
Packager:     feedback@suse.de

Copyright:    1992-95 Andrew Tridgell, Karl Auer, Jeremy Allison
Group:        Networking/Daemons
Url:          http://www.samba.org
Provides:     samba smbfs 
Requires:     smbclnt
Autoreqprov:  on
Version:      2.2
Summary:      An SMB file server for Unix
Source: samba-2.2.0-alpha0.tar.gz
Source1: samba.pamd
Patch: samba-2.2.0-alpha0.dif
%package -n smbclnt
Summary:      Samba client utilities
Autoreqprov:  on
Group:        Networking
%prep
%setup -n samba-2.2.0-alpha0
%patch

%build
cd source
%{?suse_update_config:%{suse_update_config -f}}
LIBS=-lnsl \
./configure --prefix=/usr --libdir=/etc \
	--with-privatedir=/etc --localstatedir=/var/log \
	--with-smbmount --with-pam \
	--mandir=%{_mandir} \
	--with-swatdir=/usr/lib/samba/swat \
	--with-sambabook=/usr/lib/samba/swat/using_samba
cd ..
make LOCKDIR=/var/lock/samba SBINDIR=/usr/sbin \
	CODEPAGEDIR=/usr/lib/samba/codepages -C source

%install
mkdir -p /usr/lib/samba
make install LOCKDIR=/var/lock/samba SBINDIR=/usr/sbin \
	CODEPAGEDIR=/usr/lib/samba/codepages -C source
# cleanup docs
rm -rf docs/*.[0-9]
chmod 644 `find docs examples -type f`
chmod 755 `find docs examples -type d`
#utility scripts
mkdir -p /usr/lib/samba/scripts
cp -a source/script/* /usr/lib/samba/scripts
# configuration files
install -m 644 smb.conf /etc/smb.conf
install -m 644 lmhosts /etc/lmhosts
install -m 600 smbpasswd -o root -g root /etc/smbpasswd
install -d 755 /etc/pam.d
install -m 644 $RPM_SOURCE_DIR/samba.pamd /etc/pam.d/samba
install -m 755 mount.smbfs /sbin/mount.smbfs
# start script
install rc /sbin/init.d/smb
ln -sf ../smb /sbin/init.d/rc2.d/S20smb
ln -sf ../smb /sbin/init.d/rc2.d/K20smb
ln -sf ../smb /sbin/init.d/rc3.d/S20smb
ln -sf ../smb /sbin/init.d/rc3.d/K20smb
ln -sf ../../sbin/init.d/smb /usr/sbin/rcsmb
install smbfs /sbin/init.d/smbfs
ln -sf ../smbfs /sbin/init.d/rc2.d/S21smbfs
ln -sf ../smbfs /sbin/init.d/rc2.d/K19smbfs
ln -sf ../smbfs /sbin/init.d/rc3.d/S21smbfs
ln -sf ../smbfs /sbin/init.d/rc3.d/K19smbfs
ln -sf ../../sbin/init.d/smbfs /usr/sbin/rcsmbfs
# rc.config fragment
mkdir -p /var/adm/fillup-templates
cp rc.config.samba /var/adm/fillup-templates
%{?suse_check}

%post
echo "Updating etc/rc.config..."
if [ -x bin/fillup ] ; then
  bin/fillup -q -d = etc/rc.config var/adm/fillup-templates/rc.config.samba
else
  echo "ERROR: fillup not found. This should not happen. Please compare"
  echo "etc/rc.config and var/adm/fillup-templates/rc.config.samba and"
  echo "update by hand."
fi
if grep -q '^[#[:space:]]*swat' etc/inetd.conf ; then
   echo /etc/inetd.conf is up to date
else
   echo updating inetd.conf
   cat >> etc/inetd.conf << EOF
# swat is the Samba Web Administration Tool
swat    stream  tcp     nowait.400  root    /usr/sbin/swat swat
EOF
fi
if grep -q '^swat' etc/services ; then
   echo /etc/services is up to date
else
   echo updating services
   cat >> etc/services << EOF
swat            901/tcp		# swat is the Samba Web Administration Tool
EOF
fi
mkdir -p var/adm/notify/messages
cat << EOF > var/adm/notify/messages/samba-notify
Achtung!
========
Die Syntax des smbmount Kommandos hat sich geaendert!
smbmount kann nicht mehr direkt aufgerufen werden. Es wird von einem
Shellscript /sbin/mount.smbfs aufgerufen, welches wiederum von mount
aufgerufen wird.
Hier ein Beispielaufruf:
mount -t smbfs -o username=uname,password=passwd //smbserv/share /destination
*****************************************************************************
Attention!
==========
The syntax of smbmount has changed!
smbmount can not be called direct anymore. It will be called by a shell
script /sbin/mount.smbfs, which will be called by mount.
A sample call to smbfs:
mount -t smbfs -o username=uname,password=passwd //smbserv/share /destination
EOF

%files
%config(noreplace) /etc/smb.conf
%config(noreplace) /etc/lmhosts
%config(noreplace) /etc/smbpasswd
%config /etc/pam.d/samba
/usr/lib/samba
/sbin/init.d/rc2.d/K20smb
/sbin/init.d/rc2.d/S20smb
/sbin/init.d/rc3.d/K20smb
/sbin/init.d/rc3.d/S20smb
%config /sbin/init.d/smb
/usr/bin/addtosmbpass
/usr/bin/convert_smbpasswd
/usr/bin/make_printerdef
/usr/bin/make_smbcodepage
/usr/bin/make_unicodemap
/usr/bin/smbpasswd
/usr/bin/smbstatus
/usr/bin/testparm
/usr/bin/testprns
%doc docs/* examples
%doc %{_mandir}/man1/make_smbcodepage.1.gz
%doc %{_mandir}/man1/make_unicodemap.1.gz
%doc %{_mandir}/man1/smbrun.1.gz
%doc %{_mandir}/man1/smbsh.1.gz
%doc %{_mandir}/man1/smbstatus.1.gz
%doc %{_mandir}/man1/testparm.1.gz
%doc %{_mandir}/man1/testprns.1.gz
%doc %{_mandir}/man5/lmhosts.5.gz
%doc %{_mandir}/man5/smb.conf.5.gz
%doc %{_mandir}/man5/smbpasswd.5.gz
%doc %{_mandir}/man7/samba.7.gz
%doc %{_mandir}/man8/nmbd.8.gz
%doc %{_mandir}/man8/smbd.8.gz
%doc %{_mandir}/man8/smbpasswd.8.gz
%doc %{_mandir}/man8/swat.8.gz
/usr/sbin/nmbd
/usr/sbin/rcsmb
/usr/sbin/smbd
/usr/sbin/swat
/var/adm/fillup-templates/rc.config.samba

%files -n smbclnt
/sbin/init.d/rc2.d/K19smbfs
/sbin/init.d/rc2.d/S21smbfs
/sbin/init.d/rc3.d/K19smbfs
/sbin/init.d/rc3.d/S21smbfs
%config /sbin/init.d/smbfs
/usr/sbin/rcsmbfs
/sbin/mount.smbfs
/usr/bin/nmblookup
/usr/bin/rpcclient
/usr/bin/smbclient
/usr/bin/smbmnt
/usr/bin/smbmount
/usr/bin/smbumount
/usr/bin/smbspool
/usr/bin/smbtar
%doc %{_mandir}/man1/nmblookup.1.gz
%doc %{_mandir}/man1/smbclient.1.gz
%doc %{_mandir}/man1/smbtar.1.gz
%doc %{_mandir}/man8/smbmnt.8.gz
%doc %{_mandir}/man8/smbmount.8.gz
%doc %{_mandir}/man8/smbspool.8.gz
%doc %{_mandir}/man8/smbumount.8.gz

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


%description -n smbclnt
This package contains all programs, that are needed to act as a samba
client. This includes also smbmount, of course.

Authors:
--------
    Andrew Tridgell <Andrew.Tridgell@anu.edu.au>
    Karl Auer <Karl.Auer@anu.edu.au>
    Jeremy Allison <jeremy@netcom.com>

SuSE series: n


%changelog -n samba
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
  the multilined configure call missed a "" :-(
* Thu Mar 09 2000 - choeger@suse.de
- fixed typo in specfile
* Wed Mar 01 2000 - choeger@suse.de
- added %{_mandir}
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
