Summary: SMB client and server
Name: samba
%define	version 1.9.17
Version: %{version}
Release: 6
Copyright: GPL
Group: Networking
Source: ftp://samba.anu.edu.au/pub/samba/samba-%{version}.tar.gz
Patch: samba-make.patch
Patch2: samba-axp.patch
Packager: John H Terpstra [Samba-Team] <jht@aquasoft.com.au>
Requires: 
BuildRoot: /tmp/samba

%description
Samba provides an SMB server which can be used to provide network
services to SMB (sometimes called "Lan Manager") clients, including
various versions of MS Windows, OS/2, and other Linux machines.
Samba also provides some SMB clients, which complement the built-in
SMB filesystem in Linux.

Samba uses NetBIOS over TCP/IP (NetBT) protocols and does NOT need
NetBEUI (Microsoft Raw NetBIOS frame) protocol.

This release provides enhanced browsing and protocol support and
has been called - The BROWSE FIX release.

%prep
%setup
%patch -p1

%ifarch axp alpha
%patch2 -p1
%endif

%build
cd source
make RPM_OPT_FLAGS="$RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/etc
mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d
mkdir -p $RPM_BUILD_ROOT/etc/pam.d
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/rc0.d
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/rc1.d
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/rc2.d
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/rc3.d
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/rc5.d
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/rc6.d
mkdir -p $RPM_BUILD_ROOT/home/samba
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/usr/man/man1
mkdir -p $RPM_BUILD_ROOT/usr/man/man5
mkdir -p $RPM_BUILD_ROOT/usr/man/man7
mkdir -p $RPM_BUILD_ROOT/usr/man/man8
mkdir -p $RPM_BUILD_ROOT/var/lock/samba
mkdir -p $RPM_BUILD_ROOT/var/log/samba
mkdir -p $RPM_BUILD_ROOT/var/spool/samba

cd source
cd ..
for i in nmblookup smbclient smbpasswd smbrun smbstatus testparm testprns
do
install -m755 -s source/$i $RPM_BUILD_ROOT/usr/bin
done

for i in addtosmbpass mksmbpasswd.sh smbtar 
do
install -m755 source/$i $RPM_BUILD_ROOT/usr/bin
done

for i in smbd nmbd
do
install -m755 -s source/$i $RPM_BUILD_ROOT/usr/sbin
done

for i in smbclient.1 smbrun.1 smbstatus.1 smbtar.1 testparm.1 testprns.1
do
install -m644 docs/$i $RPM_BUILD_ROOT/usr/man/man1
done

install -m644 docs/smb.conf.5 $RPM_BUILD_ROOT/usr/man/man5
install -m644 docs/samba.7 $RPM_BUILD_ROOT/usr/man/man7
install -m644 docs/smbd.8 $RPM_BUILD_ROOT/usr/man/man8
install -m644 docs/nmbd.8 $RPM_BUILD_ROOT/usr/man/man8
install -m644 examples/simple/smb.conf $RPM_BUILD_ROOT/etc/smb.conf.sampl
install -m644 examples/redhat/smb.conf $RPM_BUILD_ROOT/etc/smb.conf
install -m755 examples/redhat/smbprint $RPM_BUILD_ROOT/usr/bin
install -m755 examples/redhat/smb.init $RPM_BUILD_ROOT/etc/rc.d/init.d/smb
install -m755 examples/redhat/smb.init $RPM_BUILD_ROOT/usr/sbin/samba
install -m644 examples/redhat/samba.pamd $RPM_BUILD_ROOT/etc/pam.d/samba
install -m644 examples/redhat/samba.log $RPM_BUILD_ROOT/etc/logrotate.d/samba

ln -sf /etc/rc.d/init.d/smb $RPM_BUILD_ROOT/etc/rc.d/rc0.d/K35smb
ln -sf /etc/rc.d/init.d/smb $RPM_BUILD_ROOT/etc/rc.d/rc1.d/K35smb
ln -sf /etc/rc.d/init.d/smb $RPM_BUILD_ROOT/etc/rc.d/rc2.d/K35smb
ln -sf /etc/rc.d/init.d/smb $RPM_BUILD_ROOT/etc/rc.d/rc3.d/S91smb
ln -sf /etc/rc.d/init.d/smb $RPM_BUILD_ROOT/etc/rc.d/rc5.d/S91smb
ln -sf /etc/rc.d/init.d/smb $RPM_BUILD_ROOT/etc/rc.d/rc6.d/K35smb

%clean
rm -rf $RPM_BUILD_ROOT

%post
if [ "$1" = 0 ] ; then
      /sbin/pamconfig --add --service=samba --password=none --sesslist=none
fi

%postun
if [ "$1" = 0 ] ; then
  if [ -x /etc/pam.d/samba ]; then
    rm -f /etc/pam.d/samba
  else
    if [ -x /etc/pam.conf ]; then
      /sbin/pamconfig --remove --service=samba --password=none --sesslist=none
    fi
  fi
  if [ -e /var/log/samba ]; then
    rm -rf /var/log/samba
  fi
  if [ -e /var/lock/samba ]; then
    rm -rf /var/lock/samba
  fi
fi

%files
%attr(-,root,root) %doc docs/*.txt docs/INSTALL.sambatar docs/MIRRORS docs/PROJECTS 
%attr(-,root,root) %doc docs/README.DCEDFS docs/README.jis docs/README.sambatar 
%attr(-,root,root) %doc docs/SMBTAR.notes docs/THANKS docs/announce docs/history
%attr(-,root,root) %doc docs/samba.faq docs/samba.lsm docs/wfw_slip.htm 
%attr(-,root,root) %doc examples
%attr(-,root,root) /usr/sbin/smbd
%attr(-,root,root) /usr/bin/addtosmbpass
%attr(-,root,root) /usr/bin/mksmbpasswd.sh
%attr(-,root,root) /usr/bin/smbclient
%attr(-,root,root) /usr/sbin/nmbd
%attr(-,root,root) /usr/bin/testparm
%attr(-,root,root) /usr/bin/testprns
%attr(-,root,root) /usr/bin/smbrun
%attr(-,root,root) /usr/bin/smbstatus
%attr(-,root,root) /usr/bin/nmblookup
%attr(-,root,root) /usr/bin/smbpasswd
%attr(-,root,root) /usr/bin/smbtar
%attr(-,root,root) /usr/bin/smbprint
%attr(-,root,root) %config /etc/smb.conf
%attr(-,root,root) %config /etc/smb.conf.sampl
%attr(-,root,root) %config /etc/rc.d/init.d/smb
%attr(755,root,root) %config /usr/sbin/samba
%attr(-,root,root) %config /etc/rc.d/rc3.d/S91smb
%attr(-,root,root) %config /etc/rc.d/rc5.d/S91smb
%attr(-,root,root) %config /etc/rc.d/rc0.d/K35smb
%attr(-,root,root) %config /etc/rc.d/rc1.d/K35smb
%attr(-,root,root) %config /etc/rc.d/rc6.d/K35smb
%attr(-,root,root) %config /etc/rc.d/rc2.d/K35smb
%attr(-,root,root) %config /etc/logrotate.d/samba
%attr(-,root,root) %config /etc/pam.d/samba
%attr(-,root,root) /usr/man/man1/smbstatus.1
%attr(-,root,root) /usr/man/man1/smbclient.1
%attr(-,root,root) /usr/man/man1/smbrun.1
%attr(-,root,root) /usr/man/man1/smbtar.1
%attr(-,root,root) /usr/man/man1/testparm.1
%attr(-,root,root) /usr/man/man1/testprns.1
%attr(-,root,root) /usr/man/man5/smb.conf.5
%attr(-,root,root) /usr/man/man7/samba.7
%attr(-,root,root) /usr/man/man8/smbd.8
%attr(-,root,root) /usr/man/man8/nmbd.8
%attr(-,root,nobody) %dir /home/samba
%attr(-,root,root) %dir /var/lock/samba
%attr(-,root,root) %dir /var/log/samba
%attr(777,root,root) %dir /var/spool/samba
