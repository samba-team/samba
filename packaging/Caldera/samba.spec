Summary: SMB client and server
Name: samba
Version: 1.9.18p7
Release: Caldera.1
Copyright: GPL
Group: Networking
Source: ftp://samba.anu.edu.au/pub/samba/samba-1.9.18p7.tar.gz
Patch: samba-make.patch
Packager: John H Terpstra [Samba-Team] <jht@samba.anu.edu.au>
Requires: libpam >= 0.56
BuildRoot: /tmp/samba

%description
Samba provides an SMB server which can be used to provide
network services to SMB (sometimes called "Lan Manager")
clients, including various versions of MS Windows, OS/2,
and other Linux machines. Samba also provides some SMB
clients, which complement the built-in SMB filesystem
in Linux. Samba uses NetBIOS over TCP/IP (NetBT) protocols
and does NOT need NetBEUI (Microsoft Raw NetBIOS frame)
protocol.

This release is known as the "Locking Update" and has full
support for Opportunistic File Locking. In addition this update
includes native support for Microsoft encrypted passwords,
improved browse list and WINS database management.

Please refer to the WHATSNEW.txt document for fixup information.
This binary release includes encrypted password support.
Please read the smb.conf file and ENCRYPTION.txt in the
docs directory for implementation details.

NOTE: Caldera Open Linux Uses PAM which has integrated support
for Shadow passwords. Do NOT recompile with the SHADOW_PWD option
enabled. Caldera Open Linux has built in support for quotas in PAM.

%prep
%setup
%patch -p1

%build
cd source
make RPM_OPT_FLAGS="$RPM_OPT_FLAGS"
make RPM_OPT_FLAGS="$RPM_OPT_FLAGS" wsmbconf

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/etc
mkdir -p $RPM_BUILD_ROOT/etc/codepages
mkdir -p $RPM_BUILD_ROOT/etc/codepages/src
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
mkdir -p $RPM_BUILD_ROOT/usr/doc/samba-1.9.18p5-Caldera.2
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/usr/man/man1
mkdir -p $RPM_BUILD_ROOT/usr/man/man5
mkdir -p $RPM_BUILD_ROOT/usr/man/man7
mkdir -p $RPM_BUILD_ROOT/usr/man/man8
mkdir -p $RPM_BUILD_ROOT/var/lock/samba
mkdir -p $RPM_BUILD_ROOT/var/log/samba
mkdir -p $RPM_BUILD_ROOT/var/spool/samba

for i in nmblookup smbclient smbpasswd smbrun smbstatus testparm testprns
do
install -m755 -s source/$i $RPM_BUILD_ROOT/usr/bin
done

for i in addtosmbpass mksmbpasswd.sh smbtar make_smbcodepage make_printerdef
do
install -m755 source/$i $RPM_BUILD_ROOT/usr/bin
done

for i in smbd nmbd wsmbconf
do
install -m755 -s source/$i $RPM_BUILD_ROOT/usr/sbin
done

for i in smbclient.1 smbrun.1 smbstatus.1 smbtar.1 testparm.1 testprns.1 make_smbcodepage.1
do
install -m644 docs/$i $RPM_BUILD_ROOT/usr/man/man1
done

for i in 437 850 852 866 932 949 950 936
do
install -m644 source/codepage_def.$i $RPM_BUILD_ROOT/etc/codepages/src
done

install -m644 docs/smb.conf.5 $RPM_BUILD_ROOT/usr/man/man5
install -m644 docs/samba.7 $RPM_BUILD_ROOT/usr/man/man7
install -m644 docs/smbd.8 $RPM_BUILD_ROOT/usr/man/man8
install -m644 docs/nmbd.8 $RPM_BUILD_ROOT/usr/man/man8
install -m644 docs/smbpasswd.8 $RPM_BUILD_ROOT/usr/man/man8
install -m644 packaging/Caldera/smb.conf $RPM_BUILD_ROOT/etc/smb.conf
install -m644 packaging/Caldera/smbusers $RPM_BUILD_ROOT/etc/smbusers
install -m755 packaging/Caldera/smbprint $RPM_BUILD_ROOT/usr/bin
install -m755 packaging/Caldera/smbadduser $RPM_BUILD_ROOT/usr/bin
install -m755 packaging/Caldera/smb.init $RPM_BUILD_ROOT/etc/rc.d/init.d/smb
install -m755 packaging/Caldera/smb.init $RPM_BUILD_ROOT/usr/sbin/samba
install -m644 packaging/Caldera/samba.pamd $RPM_BUILD_ROOT/etc/pam.d/samba
install -m644 packaging/Caldera/samba.log $RPM_BUILD_ROOT/etc/logrotate.d/samba

ln -sf /etc/rc.d/init.d/smb $RPM_BUILD_ROOT/etc/rc.d/rc0.d/K35smb
ln -sf /etc/rc.d/init.d/smb $RPM_BUILD_ROOT/etc/rc.d/rc1.d/K35smb
ln -sf /etc/rc.d/init.d/smb $RPM_BUILD_ROOT/etc/rc.d/rc2.d/K35smb
ln -sf /etc/rc.d/init.d/smb $RPM_BUILD_ROOT/etc/rc.d/rc3.d/S91smb
ln -sf /etc/rc.d/init.d/smb $RPM_BUILD_ROOT/etc/rc.d/rc5.d/S91smb
ln -sf /etc/rc.d/init.d/smb $RPM_BUILD_ROOT/etc/rc.d/rc6.d/K35smb

for i in README COPYING Manifest Read-Manifest-Now WHATSNEW.txt Roadmap docs examples
do
cp -avf $i $RPM_BUILD_ROOT/usr/doc/samba-1.9.18p5-Caldera.2
done

%clean
rm -rf $RPM_BUILD_ROOT

%post
for i in 437 850 852 866 932 949 950 936
do
/usr/bin/make_smbcodepage c $i /etc/codepages/src/codepage_def.$i /etc/codepages/codepage.$i
done

%postun
if [ -x /etc/pam.d/samba ]; then
  rm -f /etc/pam.d/samba
fi
if [ -e /etc/codepages ]; then
  rm -rf /etc/codepages
fi
if [ -e /var/log/samba ]; then
  rm -rf /var/log/samba
fi
if [ -e /var/lock/samba ]; then
  rm -rf /var/lock/samba
fi

%files
%attr(-,root,root) %doc README COPYING Manifest Read-Manifest-Now
%attr(-,root,root) %doc WHATSNEW.txt Roadmap
%attr(-,root,root) %doc docs
%attr(-,root,root) %doc examples
%attr(-,root,root) /usr/sbin/smbd
%attr(-,root,root) /usr/sbin/nmbd
%attr(2755,root,root) /usr/sbin/wsmbconf
%attr(-,root,root) /usr/bin/addtosmbpass
%attr(-,root,root) /usr/bin/mksmbpasswd.sh
%attr(-,root,root) /usr/bin/smbclient
%attr(-,root,root) /usr/bin/testparm
%attr(-,root,root) /usr/bin/testprns
%attr(-,root,root) /usr/bin/smbrun
%attr(-,root,root) /usr/bin/smbstatus
%attr(-,root,root) /usr/bin/nmblookup
%attr(-,root,root) /usr/bin/make_smbcodepage
%attr(-,root,root) /usr/bin/make_printerdef
%attr(-,root,root) /usr/bin/smbpasswd
%attr(-,root,root) /usr/bin/smbtar
%attr(-,root,root) /usr/bin/smbprint
%attr(-,root,root) /usr/bin/smbadduser
%attr(-,root,root) %config /etc/smb.conf
%attr(-,root,root) %config /etc/smbusers
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
%attr(-,root,root) %config /etc/codepages/src/codepage_def.437
%attr(-,root,root) %config /etc/codepages/src/codepage_def.850
%attr(-,root,root) %config /etc/codepages/src/codepage_def.852
%attr(-,root,root) %config /etc/codepages/src/codepage_def.866
%attr(-,root,root) %config /etc/codepages/src/codepage_def.932
%attr(-,root,root) %config /etc/codepages/src/codepage_def.936
%attr(-,root,root) %config /etc/codepages/src/codepage_def.949
%attr(-,root,root) %config /etc/codepages/src/codepage_def.950
%attr(-,root,root) /usr/man/man1/smbstatus.1
%attr(-,root,root) /usr/man/man1/smbclient.1
%attr(-,root,root) /usr/man/man1/make_smbcodepage.1
%attr(-,root,root) /usr/man/man1/smbrun.1
%attr(-,root,root) /usr/man/man1/smbtar.1
%attr(-,root,root) /usr/man/man1/testparm.1
%attr(-,root,root) /usr/man/man1/testprns.1
%attr(-,root,root) /usr/man/man5/smb.conf.5
%attr(-,root,root) /usr/man/man7/samba.7
%attr(-,root,root) /usr/man/man8/smbd.8
%attr(-,root,root) /usr/man/man8/nmbd.8
%attr(-,root,root) /usr/man/man8/smbpasswd.8
%attr(-,root,nobody) %dir /home/samba
%attr(-,root,root) %dir /etc/codepages
%attr(-,root,root) %dir /etc/codepages/src
%attr(-,root,root) %dir /var/lock/samba
%attr(-,root,root) %dir /var/log/samba
%attr(777,root,root) %dir /var/spool/samba
