%define initdir %{_sysconfdir}/init.d

Summary: Clustered TDB
Vendor: Samba Team
Packager: Samba Team <samba@samba.org>
Name: ctdb
Version: 1.0
Release: 30
Epoch: 0
License: GNU GPL version 3
Group: System Environment/Daemons
URL: http://ctdb.samba.org/

Source: ctdb-%{version}.tar.gz

Prereq: /sbin/chkconfig /bin/mktemp /usr/bin/killall
Prereq: fileutils sed /etc/init.d

Provides: ctdb = %{version}

Prefix: /usr
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
ctdb is the clustered database used by samba


#######################################################################

%prep
%setup -q
# setup the init script and sysconfig file
%setup -T -D -n ctdb-%{version} -q

%build

CC="gcc"

## always run autogen.sh
./autogen.sh

CFLAGS="$RPM_OPT_FLAGS $EXTRA -O0 -D_GNU_SOURCE" ./configure \
	--prefix=%{_prefix} \
	--sysconfdir=%{_sysconfdir} \
	--mandir=%{_mandir} \
	--localstatedir="/var"

make showflags
make   

%install
# Clean up in case there is trash left from a previous build
rm -rf $RPM_BUILD_ROOT

# Create the target build directory hierarchy
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/init.d

make DESTDIR=$RPM_BUILD_ROOT install

install -m644 config/ctdb.sysconfig $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/ctdb
install -m755 config/ctdb.init $RPM_BUILD_ROOT%{initdir}/ctdb

# Remove "*.old" files
find $RPM_BUILD_ROOT -name "*.old" -exec rm -f {} \;

%clean
rm -rf $RPM_BUILD_ROOT

%post
[ -x /sbin/chkconfig ] && /sbin/chkconfig --add ctdb

%preun
if [ $1 = 0 ] ; then
    [ -x /sbin/chkconfig ] && /sbin/chkconfig --del ctdb
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

%{_sysconfdir}/ctdb/functions
%{_sysconfdir}/ctdb/events.d/README
%{_sysconfdir}/ctdb/events.d/00.ctdb
%{_sysconfdir}/ctdb/events.d/10.interface
%{_sysconfdir}/ctdb/events.d/40.vsftpd
%{_sysconfdir}/ctdb/events.d/41.httpd
%{_sysconfdir}/ctdb/events.d/50.samba
%{_sysconfdir}/ctdb/events.d/60.nfs
%{_sysconfdir}/ctdb/events.d/61.nfstickle
%{_sysconfdir}/ctdb/events.d/70.iscsi
%{_sysconfdir}/ctdb/events.d/90.ipmux
%{_sysconfdir}/ctdb/events.d/91.lvs
%{_sysconfdir}/ctdb/statd-callout
%{_sbindir}/ctdbd
%{_bindir}/ctdb
%{_bindir}/smnotify
%{_bindir}/ctdb_ipmux
%{_bindir}/ctdb_diagnostics
%{_bindir}/onnode.ssh
%{_bindir}/onnode.rsh
%{_bindir}/onnode
%{_mandir}/man1/ctdb.1.gz
%{_mandir}/man1/ctdbd.1.gz
%{_mandir}/man1/onnode.1.gz
%{_includedir}/ctdb.h
%{_includedir}/ctdb_private.h

%changelog
* Tue Mar 04 2008 : Version 1.0.30
 - Update documentation cor new commands and tuneables
 - Add machinereadable output to the ip,uptime and getdebug commands
 - Add a moveip command to manually failover/failback public ips
 - Add NoIPFallback tuneable that prevents ip address failback
 - Use file locking inside the CFS as alternative to verify when other nodes
   Are connected/disconnected to be able to recover from split network
 - Add DisableWhenUnhealthy tunable
 - Add CTDB_START_AS_DISABLED sysconfig param
 - Add --start-as-disabled flag to ctdb
 - Add ability to monitor for OOM condition
* Thu Feb 21 2008 : Version 1.0.29
 - Add a new command to make expansion of an existing cluster easier
 - Fix bug with references to freed objects in the ctdb structure
 - Propagate debuglevel changes to the recovery daemon
 - Merge patches to event scripts from Mathieu Parent :
 - MP: Simulate "service" on systems which do not provide this tool
 - MP: Set correct permissions for events.d/README
 - Add nice helper functions to start/stop nfs from the event scripts
* Fri Feb 08 2008 : Version 1.0.28
 - Fix a problem where we tried to use ethtool on non-ethernet interfaces
 - Warn if the ipvsadm packege is missing when LVS is used
 - Dont use absolute pathnames in some of the event scripts
 - Fix for persistent tdbs growing inifinitely.
* Wed Feb 06 2008 : Version 1.0.27
 - Add eventscript for iscsi
* Thu Jan 31 2008 : Version 1.0.26
 - Fix crashbug in tdb transaction code
* Tue Jan 29 2008 : Version 1.0.25
 - added async recovery code
 - make event scripts more portable
 - fixed ctdb dumpmemory
 - more efficient tdb allocation code
 - improved machine readable ctdb status output
 - added ctdb uptime
* Wed Jan 16 2008 : Version 1.0.24
 - added syslog support
 - documentation updates
* Wed Jan 16 2008 : Version 1.0.23
 - fixed a memory leak in the recoveryd
 - fixed a corruption bug in the new transaction code
 - fixed a case where an packet for a disconnected client could be processed
 - added http event script
 - updated documentation
* Thu Jan 10 2008 : Version 1.0.22
 - auto-run vacuum and repack ops
* Wed Jan 09 2008 : Version 1.0.21
 - added ctdb vacuum and ctdb repack code
* Sun Jan 06 2008 : Version 1.0.20
 - new transaction based recovery code
* Sat Jan 05 2008 : Version 1.0.19
 - fixed non-master bug
 - big speedup in recovery for large databases
 - lots of changes to improve tdb and ctdb for high churn databases
* Thu Dec 27 2007 : Version 1.0.18
 - fixed crash bug in monitor_handler
* Tue Dec 04 2007 : Version 1.0.17
 - fixed bugs related to ban/unban of nodes
 - fixed a race condition that could lead to monitoring being permanently disabled,
   which would lead to long recovery times
 - make deterministic IPs the default
 - fixed a bug related to continuous recovery 
 - added a debugging option --node-ip
