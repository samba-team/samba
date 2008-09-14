%define initdir %{_sysconfdir}/rc.d/init.d

Summary: Clustered TDB
Vendor: Samba Team
Packager: Samba Team <samba@samba.org>
Name: ctdb
Version: 1.0
Release: 1
Epoch: 0
License: GNU GPL version 2
Group: System Environment/Daemons
URL: bzr://www.samba.org/~tridge/ctdb/

Source: ctdb-%{version}.tar.bz2
Source999: ctdb-setup.tar.bz2

Prereq: /sbin/chkconfig /bin/mktemp /usr/bin/killall
Prereq: fileutils sed /etc/init.d

Requires: initscripts >= 5.54-1
Provides: ctdb = %{version}

Prefix: /usr
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
ctdb is the clustered database used by samba


#######################################################################

%prep
%setup -q
# setup the init script and sysconfig file
%setup -T -D -a 999 -n ctdb-%{version} -q

%build

CC="gcc"

## always run autogen.sh
./autogen.sh

CFLAGS="$RPM_OPT_FLAGS $EXTRA -D_GNU_SOURCE" ./configure \
	--prefix=%{_prefix} \
	--sysconfdir=%{_sysconfdir} \
	--localstatedir="/var"

make showflags
make   

%install
# Clean up in case there is trash left from a previous build
rm -rf $RPM_BUILD_ROOT

# Create the target build directory hierarchy
mkdir -p $RPM_BUILD_ROOT%{_includedir}
mkdir -p $RPM_BUILD_ROOT{%{_libdir},%{_includedir}}
mkdir -p $RPM_BUILD_ROOT%{_prefix}/{bin,sbin}
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/ctdb
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/rc.d/init.d

make DESTDIR=$RPM_BUILD_ROOT install

install -m644 setup/ctdb.sysconfig $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/ctdb
install -m755 setup/ctdb.init $RPM_BUILD_ROOT%{initdir}/ctdb
install -m755 tools/events $RPM_BUILD_ROOT%{_sysconfdir}/ctdb/events
install -m755 tools/onnode.ssh $RPM_BUILD_ROOT%{_bindir}
install -m755 tools/onnode.rsh $RPM_BUILD_ROOT%{_bindir}
ln -sf %{_bindir}/onnode.ssh $RPM_BUILD_ROOT%{_bindir}/onnode

# unfortunately samba3 needs ctdb_private.h too
install -m644 include/ctdb_private.h $RPM_BUILD_ROOT%{_includedir}/ctdb_private.h


# Remove "*.old" files
find $RPM_BUILD_ROOT -name "*.old" -exec rm -f {} \;

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/chkconfig --add ctdb

%preun
if [ $1 = 0 ] ; then
    /sbin/chkconfig --del ctdb
    /sbin/service ctdb stop >/dev/null 2>&1
fi
exit 0

%postun
if [ "$1" -ge "1" ]; then
	%{initdir}/ctdb restart >/dev/null 2>&1
fi	


#######################################################################
## Files section                                                     ##
#######################################################################

%files
%defattr(-,root,root)

%config(noreplace) %{_sysconfdir}/sysconfig/ctdb
%attr(755,root,root) %config %{initdir}/ctdb

%{_sysconfdir}/ctdb/events
%{_sbindir}/ctdbd
%{_bindir}/ctdb
%{_bindir}/onnode.ssh
%{_bindir}/onnode.rsh
%{_bindir}/onnode
%{_includedir}/ctdb.h
%{_includedir}/ctdb_private.h

