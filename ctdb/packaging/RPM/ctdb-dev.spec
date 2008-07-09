%define initdir %{_sysconfdir}/init.d

Summary: Clustered TDB
Vendor: Samba Team
Packager: Samba Team <samba@samba.org>
Name: ctdb-dev
Version: 1.0
Release: 45
Epoch: 0
License: GNU GPL version 3
Group: System Environment/Daemons
URL: http://ctdb.samba.org/

Source: ctdb-%{version}.tar.gz

Prereq: /sbin/chkconfig /bin/mktemp /usr/bin/killall
Prereq: fileutils sed /etc/init.d

Provides: ctdb-dev = %{version}

Prefix: /usr
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
development files for ctdb


#######################################################################

%prep
%setup -q
# setup the init script and sysconfig file
%setup -T -D -n ctdb-dev-%{version} -q

%build
# everything is already built when we built the main ctdb package

%install

%clean
rm -rf $RPM_BUILD_ROOT

%post

%preun

%postun


#######################################################################
## Files section                                                     ##
#######################################################################

%files
%defattr(-,root,root)

%{_includedir}/ctdb.h
%{_includedir}/ctdb_private.h

%changelog
* Wed Jul 9 2008 : Version 1.0.45
 forked off ctdb-dev for development files (ctdb.h/ctdb_private.h)

