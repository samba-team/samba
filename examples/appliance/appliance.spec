#
# Spec file for Samba appliance
#

%define _topdir /tmp

Summary: Samba appliance executables
Name: samba-appliance
Version: 0.1
Release: 1
Group: linuxcare
License: Various - GPL, LGPL and BSD
Source: %{name}-%{version}-src.tar.gz
BuildRoot: %{_topdir}/BUILD/appliance-build
Provides: winbind

%define prefix /usr/local/samba

%define tng_build_dir $RPM_BUILD_DIR/%{name}-%{version}/tng
%define head_build_dir $RPM_BUILD_DIR/%{name}-%{version}/head

%description
Samba appliance.

%changelog

%prep
%setup

%build
make config
make

%install
rm -rf $RPM_BUILD_ROOT

# Install stuff for tng binaries

mkdir -p $RPM_BUILD_ROOT%{prefix}/bin
mkdir -p $RPM_BUILD_ROOT/lib/security
cp %{tng_build_dir}/bin/samedit  $RPM_BUILD_ROOT%{prefix}/bin
cp %{tng_build_dir}/bin/winbindd $RPM_BUILD_ROOT%{prefix}/bin
cp %{tng_build_dir}/nsswitch/libnss_winbind.so $RPM_BUILD_ROOT/lib
cp %{tng_build_dir}/nsswitch/pam_winbind.so $RPM_BUILD_ROOT/lib/security

# Install stuff for source

mkdir -p $RPM_BUILD_ROOT%{prefix}/bin
mkdir -p $RPM_BUILD_ROOT%{prefix}/private
mkdir -p $RPM_BUILD_ROOT%{prefix}/lib/codepages/src
mkdir -p $RPM_BUILD_ROOT%{prefix}/man/{man1,man5,man7,man8}
mkdir -p $RPM_BUILD_ROOT%{prefix}/var/locks

# Install standard binary files
for i in nmblookup smbclient smbspool smbpasswd smbstatus testparm testprns \
      make_smbcodepage make_printerdef smbd nmbd
do
install -m755 -s %{head_build_dir}/source/bin/$i $RPM_BUILD_ROOT%{prefix}/bin
done
for i in addtosmbpass mksmbpasswd.sh smbtar 
do
install -m755 %{head_build_dir}/source/script/$i $RPM_BUILD_ROOT%{prefix}/bin
done

# Install level 1 man pages
for i in smbclient.1 smbrun.1 smbstatus.1 smbtar.1 testparm.1 testprns.1 \
      make_smbcodepage.1 nmblookup.1
do
install -m644 %{head_build_dir}/docs/manpages/$i $RPM_BUILD_ROOT%{prefix}/man/man1
done

# Install codepage source files
for i in 437 737 850 852 861 866 932 936 949 950
do
install -m644 %{head_build_dir}/source/codepages/codepage_def.$i $RPM_BUILD_ROOT%{prefix}/lib/codepages/src
done

# Install the miscellany
install -m644 %{head_build_dir}/docs/manpages/smb.conf.5 $RPM_BUILD_ROOT%{prefix}/man/man5
install -m644 %{head_build_dir}/docs/manpages/lmhosts.5 $RPM_BUILD_ROOT%{prefix}/man/man5
install -m644 %{head_build_dir}/docs/manpages/smbpasswd.5 $RPM_BUILD_ROOT%{prefix}/man/man5
install -m644 %{head_build_dir}/docs/manpages/samba.7 $RPM_BUILD_ROOT%{prefix}/man/man7
install -m644 %{head_build_dir}/docs/manpages/smbd.8 $RPM_BUILD_ROOT%{prefix}/man/man8
install -m644 %{head_build_dir}/docs/manpages/nmbd.8 $RPM_BUILD_ROOT%{prefix}/man/man8
install -m644 %{head_build_dir}/docs/manpages/winbindd.8 $RPM_BUILD_ROOT%{prefix}/man/man8
install -m644 %{head_build_dir}/docs/manpages/swat.8 $RPM_BUILD_ROOT%{prefix}/man/man8
install -m644 %{head_build_dir}/docs/manpages/smbpasswd.8 $RPM_BUILD_ROOT%{prefix}/man/man8
install -m644 %{head_build_dir}/docs/manpages/winbindd.8 $RPM_BUILD_ROOT%{prefix}/man/man8
install -m644 %{head_build_dir}/packaging/RedHat/smb.conf $RPM_BUILD_ROOT/%{prefix}/lib/smb.conf

%post

ln -sf /lib/libnss_winbind.so /lib/libnss_winbind.so.2

# Build codepage load files
for i in 437 737 850 852 861 866 932 936 949 950
do
%{prefix}/bin/make_smbcodepage c $i %{prefix}/lib/codepages/src/codepage_def.$i %{prefix}/lib/codepages/codepage.$i
done

%preun
if [ $1 = 0 ] ; then

    # Remove compiled codepages

    for i in 437 737 850 852 861 866 932 936 949 950; do
      rm -f %{prefix}/lib/codepages/codepage.$i
    done

#    for n in %{prefix}/lib/codepages/*; do
#	if [ $n != %{prefix}/lib/codepages/src ]; then
#	    rm -rf $n
#	fi
#    done
    # We want to remove the browse.dat and wins.dat files so they can not interfer with a new version of samba!
    if [ -e %{prefix}/var/locks/browse.dat ]; then
	    rm -f %{prefix}/var/locks/browse.dat
    fi
    if [ -e %{prefix}/var/locks/wins.dat ]; then
	    rm -f %{prefix}/var/locks/wins.dat
    fi
fi
rm -f /lib/libnss_winbind.so.2

%clean
rm -rf $RPM_BUILD_ROOT

%files
%attr(-,root,root) %{prefix}/bin/winbindd
%attr(-,root,root) %{prefix}/bin/samedit
%attr(-,root,root) /lib/libnss_winbind.so
%attr(-,root,root) /lib/security/pam_winbind.so
%attr(-,root,root) %{prefix}/bin/smbclient
%attr(-,root,root) %{prefix}/bin/smbspool
%attr(-,root,root) %{prefix}/bin/smbpasswd
%attr(-,root,root) %{prefix}/bin/smbstatus
%attr(-,root,root) %{prefix}/bin/testparm
%attr(-,root,root) %{prefix}/bin/testprns
%attr(-,root,root) %{prefix}/bin/make_smbcodepage
%attr(-,root,root) %{prefix}/bin/make_printerdef
%attr(-,root,root) %{prefix}/bin/addtosmbpass
%attr(-,root,root) %{prefix}/bin/smbtar
%attr(-,root,root) %{prefix}/bin/nmblookup
%attr(-,root,root) %{prefix}/bin/smbd
%attr(-,root,root) %{prefix}/bin/nmbd
%attr(-,root,root) %config(noreplace) %{prefix}/lib/smb.conf
%attr(-,root,root) %dir %{prefix}/lib/codepages
%attr(-,root,root) %dir %{prefix}/lib/codepages/src
%attr(-,root,root) %dir %{prefix}/var
%attr(0700,root,root) %dir %{prefix}/private
%attr(-,root,root) %{prefix}/man/man1/smbstatus.1
%attr(-,root,root) %{prefix}/man/man1/smbclient.1
%attr(-,root,root) %{prefix}/man/man1/make_smbcodepage.1
%attr(-,root,root) %{prefix}/man/man1/smbrun.1
%attr(-,root,root) %{prefix}/man/man1/smbtar.1
%attr(-,root,root) %{prefix}/man/man1/testparm.1
%attr(-,root,root) %{prefix}/man/man1/testprns.1
%attr(-,root,root) %{prefix}/man/man1/nmblookup.1
%attr(-,root,root) %{prefix}/man/man5/smb.conf.5
%attr(-,root,root) %{prefix}/man/man5/lmhosts.5
%attr(-,root,root) %{prefix}/man/man5/smbpasswd.5
%attr(-,root,root) %{prefix}/man/man7/samba.7
%attr(-,root,root) %{prefix}/man/man8/smbd.8
%attr(-,root,root) %{prefix}/man/man8/nmbd.8
%attr(-,root,root) %{prefix}/man/man8/winbindd.8
%attr(-,root,root) %{prefix}/man/man8/smbpasswd.8
%attr(-,root,root) %{prefix}/lib/codepages/src/codepage_def.437
%attr(-,root,root) %{prefix}/lib/codepages/src/codepage_def.737
%attr(-,root,root) %{prefix}/lib/codepages/src/codepage_def.850
%attr(-,root,root) %{prefix}/lib/codepages/src/codepage_def.852
%attr(-,root,root) %{prefix}/lib/codepages/src/codepage_def.861
%attr(-,root,root) %{prefix}/lib/codepages/src/codepage_def.866
%attr(-,root,root) %{prefix}/lib/codepages/src/codepage_def.932
%attr(-,root,root) %{prefix}/lib/codepages/src/codepage_def.936
%attr(-,root,root) %{prefix}/lib/codepages/src/codepage_def.949
%attr(-,root,root) %{prefix}/lib/codepages/src/codepage_def.950
