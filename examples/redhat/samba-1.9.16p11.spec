Summary: SMB client and server
Name: samba
Version: 1.9.16p11
Release: 3
Copyright: GPL
Group: Networking
Source: ftp://samba.anu.edu.au/pub/samba/samba-1.9.16p11.tar.gz
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
cd ..
for i in addtosmbpass mksmbpasswd.sh nmblookup smbclient smbpasswd smbrun smbstatus smbtar testparm testprn
do
	install -m755 -s -g 0 -o 0 source/$i /usr/bin
done
for i in smbd nmbd
do
	install -m755 -s -g 0 -o 0 source/$i /usr/sbin
done
for i in smbclient.1 smbrun.1 smbstatus.1 smbtar.1 testparm.1 testprn.1
do
	install -m644 -g 0 -o 0 docs/$i /usr/man/man1
done
install -m644 -g 0 -o 0 docs/smb.conf.5 /usr/man/man5
install -m644 -g 0 -o 0 docs/samba.7 /usr/man/man7
install -m644 -g 0 -o 0 docs/smbd.8 /usr/man/man8
install -m644 -g 0 -o 0 docs/nmbd.8 /usr/man/man8
install -m644 examples/simple/smb.conf /etc/smb.conf.sampl
install -m644 examples/redhat/smb.conf /etc/smb.conf
install -m755 examples/redhat/smb.init /etc/rc.d/init.d/smb
ln -sf /etc/rc.d/init.d/smb /etc/rc.d/rc3.d/S91smb
ln -sf /etc/rc.d/init.d/smb /etc/rc.d/rc0.d/K35smb
ln -sf /etc/rc.d/init.d/smb /etc/rc.d/rc6.d/K35smb
ln -sf /etc/rc.d/init.d/smb /etc/rc.d/rc1.d/K35smb
mkdir -p /home/samba
mkdir -p /var/lock/samba
chown root.nobody /home/samba
chmod 775 /home/samba
install -m 644 -o 0 -g 0 examples/redhat/samba.log /etc/logrotate.d/samba

%post
/sbin/pamconfig --add --service=samba --password=none --sesslist=none

if [ ! -f /var/log/samba ]; then
	touch /var/log/samba
	chmod 600 /var/log/samba
fi

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
/usr/bin/addtosmbpass
/usr/bin/mksmbpasswd.sh
/usr/bin/smbclient
/usr/sbin/nmbd
/usr/bin/testparm
/usr/bin/testprns
/usr/bin/smbrun
/usr/bin/smbstatus
/usr/bin/nmblookup
/usr/bin/smbpasswd
/usr/bin/smbtar
%config /etc/smb.conf
%config /etc/smb.conf.sampl
%config /etc/rc.d/init.d/smb
%config /etc/rc.d/rc3.d/S91smb
%config /etc/rc.d/rc0.d/K35smb
%config /etc/rc.d/rc1.d/K35smb
%config /etc/rc.d/rc6.d/K35smb
%config /etc/logrotate.d/samba
/usr/man/man1/smbstatus.1
/usr/man/man1/smbclient.1
/usr/man/man1/smbrun.1
/usr/man/man1/smbtar.1
/usr/man/man1/testparm.1
/usr/man/man1/testprns.1
/usr/man/man5/smb.conf.5
/usr/man/man7/samba.7
/usr/man/man8/smbd.8
/usr/man/man8/nmbd.8
%dir /home/samba
%dir /var/lock/samba
