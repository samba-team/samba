Summary: SMB client and server
Name: samba
Version: 1.9.16p10
Release: 1
Copyright: GPL
Group: Networking
Source: ftp://samba.anu.edu.au/pub/samba/samba-1.9.16p10.tar.gz
Patch: samba-make.patch
Patch2: samba-axp.patch
Packager: John H Terpstra [Samba-Team] <jht@aquasoft.com.au>
Requires: pamconfig

%description
Samba provides an SMB server which can be used to provide network
services to SMB (sometimes called "Lan Manager") clients, including
various versions of MS Windows, OS/2, and other Linux machines.
Samba also provides some SMB clients, which complement the built-in
SMB filesystem in Linux.

Samba uses NetBIOS over TCP/IP (NetBT) protocols and does NOT need
NetBEUI (Microsoft Raw NetBIOS frame) protocol.

%prep
%setup
%patch -p1

%ifarch axp
%patch2 -p1
%endif

%build
cd source
make RPM_OPT_FLAGS="$RPM_OPT_FLAGS"

%install
cd source
make install
cd ..
install -m644 examples/simple/smb.conf /etc/smb.conf.sampl
install -m644 examples/redhat/smb.conf /etc/smb.conf
install -m755 examples/redhat/smb.init /etc/rc.d/init.d/smb
ln -sf ../init.d/smb /etc/rc.d/rc3.d/S91smb
ln -sf ../init.d/smb /etc/rc.d/rc0.d/K35smb
ln -sf ../init.d/smb /etc/rc.d/rc6.d/K35smb
ln -sf ../init.d/smb /etc/rc.d/rc1.d/K35smb
mkdir -p /home/samba
mkdir -p /var/log/samba
chown root.nobody /home/samba
chmod 775 /home/samba

strip /usr/sbin/smbd /usr/bin/smbclient /usr/sbin/nmbd /usr/bin/testparm \
	/usr/bin/testprns /usr/bin/smbrun /usr/bin/smbstatus \
	/usr/bin/nmblookup /usr/bin/smbpasswd

%post
/sbin/pamconfig --add --service=samba --password=none --sesslist=none

%postun
if [ "$1" = 0 ] ; then
  /sbin/pamconfig --remove --service=samba --password=none --sesslist=none
fi

%files
%doc docs/*.txt docs/INSTALL.sambatar docs/MIRRORS docs/PROJECTS 
%doc docs/README.DCEDFS docs/README.jis docs/README.sambatar 
%doc docs/SMBTAR.notes docs/THANKS docs/announce docs/history
%doc docs/samba.faq docs/samba.lsm docs/wfw_slip.htm 
%doc examples
/usr/sbin/smbd
/usr/bin/smbclient
/usr/sbin/nmbd
/usr/bin/testparm
/usr/bin/testprns
/usr/bin/smbrun
/usr/bin/smbstatus
/usr/bin/nmblookup
/usr/bin/smbpasswd
%config /etc/smb.conf
/etc/smb.conf.sampl
/etc/rc.d/init.d/smb
/etc/rc.d/rc3.d/S91smb
/etc/rc.d/rc0.d/K35smb
/etc/rc.d/rc1.d/K35smb
/etc/rc.d/rc6.d/K35smb
/usr/man/man1/smbstatus.1
/usr/man/man1/smbclient.1
/usr/man/man1/smbrun.1
/usr/man/man1/testparm.1
/usr/man/man1/testprns.1
/usr/man/man5/smb.conf.5
/usr/man/man7/samba.7
/usr/man/man8/smbd.8
/usr/man/man8/nmbd.8
%dir /home/samba
%dir /var/lock/samba
