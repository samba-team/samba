%define initdir %{_sysconfdir}/init.d

Summary: Clustered TDB
Vendor: Samba Team
Packager: Samba Team <samba@samba.org>
Name: ctdb
Version: 1.0.70
Release: 1
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

## check for ccache
if ccache -h >/dev/null 2>&1 ; then
	CC="ccache gcc"
else
	CC="gcc"
fi

export CC

## always run autogen.sh
./autogen.sh

CFLAGS="$RPM_OPT_FLAGS $EXTRA -O0 -D_GNU_SOURCE -DCTDB_VERS=\"%{version}-%{release}\"" ./configure \
	--prefix=%{_prefix} \
	--sysconfdir=%{_sysconfdir} \
	--mandir=%{_mandir} \
	--localstatedir="/var"

make docdir=%{_docdir} showflags
make docdir=%{_docdir}

%install
# Clean up in case there is trash left from a previous build
rm -rf $RPM_BUILD_ROOT

# Create the target build directory hierarchy
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/init.d

make DESTDIR=$RPM_BUILD_ROOT docdir=%{_docdir} install

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
	%{initdir}/ctdb restart >/dev/null 2>&1 || true
fi	


#######################################################################
## Files section                                                     ##
#######################################################################

%files
%defattr(-,root,root)

%config(noreplace) %{_sysconfdir}/sysconfig/ctdb
%config(noreplace) %{_sysconfdir}/ctdb/functions
%attr(755,root,root) %{initdir}/ctdb

%{_docdir}/ctdb/README.eventscripts
%{_docdir}/ctdb/recovery-process.txt
%{_sysconfdir}/ctdb/events.d/00.ctdb
%{_sysconfdir}/ctdb/events.d/10.interface
%{_sysconfdir}/ctdb/events.d/20.multipathd
%{_sysconfdir}/ctdb/events.d/40.vsftpd
%{_sysconfdir}/ctdb/events.d/41.httpd
%{_sysconfdir}/ctdb/events.d/50.samba
%{_sysconfdir}/ctdb/events.d/60.nfs
%{_sysconfdir}/ctdb/events.d/61.nfstickle
%{_sysconfdir}/ctdb/events.d/70.iscsi
%{_sysconfdir}/ctdb/events.d/90.ipmux
%{_sysconfdir}/ctdb/events.d/91.lvs
%{_sysconfdir}/ctdb/events.d/99.routing
%{_sysconfdir}/ctdb/statd-callout
%{_sbindir}/ctdbd
%{_bindir}/ctdb
%{_bindir}/smnotify
%{_bindir}/ctdb_ipmux
%{_bindir}/ctdb_diagnostics
%{_bindir}/onnode
%{_mandir}/man1/ctdb.1.gz
%{_mandir}/man1/ctdbd.1.gz
%{_mandir}/man1/onnode.1.gz
%{_includedir}/ctdb.h
%{_includedir}/ctdb_private.h

%changelog
* Fri Jan 16 2009 : Version 1.0.70
 - IPv6 support is completed. this is backward compatible with ipv4-only
   systems. To use IPv6 with samba and ctdb you need current GIT of samba 3.3
   or michael adams samba-ctdeb branch.
 - Many enhancements to the build system and scripts to make it more SUSE
   friendly by Michael Adams.
 - Change of how the naming of the package is structured. We are now
   using "1.0.70" as a release and "-1" as the revision instead of as
   previously using "1.0" as release and ".70" as the revision.
   By Michael Adams.
* Thu Dec 18 2008 : Version 1.0.69
 - Various fixes to scripts by M Adam
 - Dont call ctdb_fatal() when the transport is down during shutdown
* Fri Dec 12 2008 : Version 1.0.68
 - Fixes for monitoring of interfaces status from Michael Adam.
 - Use -q instead of >/dev/null for grep to enhance readability of the
   scripts from Michael Adam.
 - Update to the "ctdb recover" command. This command now block until the
   has completed. This makes it much easier to use in scripts and avoids
   the common workaround :
      ctdb recover
      ... loop while waiting for recovery completes ...
      continue ...
 - Add a CTDB_TIMEOUT variable. If set, this variable provides an automatic
   timeout for "ctdb <command>", similar to using -T <timeout>
 - Set a unique errorcode for "ctdb <command>" when it terminates due to a 
   timeout so that scripts can distinguish between a hung command and what was
   just a failure.
 - Update "ctdb ban/unban" so that if the cluster is in recovery these commands
   blocks and waits until after recovery is complete before the perform the
   ban/unban operation. This is necessary since the recovery process can cause
   nodes to become automatically unbanned.
 - Update "ctdb ban/unban" to block until the recovery that will follow shortly
   after this command has completed.
   This makes it much easier to use in scripts and avoids the common
   workaround :
      ctdb ban/unban
      ... loop while waiting for recovery completes ...
      continue ...
 - Bugfix for the new flags handling in 1.0.67. Abort and restart monitoring
   if we failed to get proper nodemaps from a remote node instead of
   dereferencing a null pointer.
 - If ctdbd was explicitely started with the '--socket' argument, make
   ctdbd automatically set CTDB_SOCKET to the specified argument.
   This ensures that eventscripts spawned by the ctdb daemon will default to
   using the same socket and talk to the correct daemon.
   This primarily affects running multiple daemons on the same host and where 
   you want each instance of ctdb daemons have their eventscripts talk to the
   "correct" daemon.
 - Update "ctdb ping" to return an error code if the ping fail so that it
   can be used in scripts.
 - Update to how to synchronize management of node flags across the cluster.
* Thu Dec 3 2008 : Version 1.0.67
 - Add a document describing the recovery process.
 - Fix a bug in "ctdb setdebug" where it would refuse to set a negative
   debug level.
 - Print the list of literals for debug names if an invalid one was given
   to "ctdb setdebug"
 - Redesign how "ctdb reloadnodes" works and reduce the amont of tcp teardowns
   used during this event.
 - Make it possible to delete a public ip from all nodes at once using
   "ctdb delip -n all"
* Mon Nov 24 2008 : Version 1.0.66
 - Allow to change the recmaster even when we are not frozen.
 - Remove two redundant SAMBA_CHECK variables from the sysconf example
 - After a node failure it can take very long before some lock operations
   ctdb needs to perform are allowed/works with gpfs again. Workaround this
   by treating a hang/timeout as success.
 - Dont override CTDB_BASE is fet in the shell already
 - Always send keepalive packets regardless of whether the link is idle or not.
 - Rewrite the disable/enable flag update logic to prevent a race between 
   "ctdb disable/enable" and the recovery daemon when updating the flags to 
   all nodes.
* Thu Nov 13 2008 : Version 1.0.65
 - Update the sysconfig example: The default debug level is 2 (NOTICE) and not
   0 (ERROR)
 - Add support for a CTDB_SOCKET environment variable for the ctdb command
   line tool. If set, this overrides the default socket the ctdb tool will
   use.
 - Add logging of high latency operations.
* Mon Oct 22 2008 : Version 1.0.64
 - Add a context and a timed event so that once we have been in recovery for
   too long we drop all public addresses.
* Mon Oct 20 2008 : Version 1.0.63
 - Remove logging of "periodic cleanup ..." in 50.samba
 - When we reload a nodes file, we must detect this and reload the file also
   in the recovery daemon before we try to dereference somethoung beyond the end
   of the nodes array.
* Thu Oct 16 2008 : Version 1.0.62
 - Allow multiple eventscritps using the same prefix number.
   It is undefined which order scripts with the same prefix will execute in.
* Wed Oct 15 2008 : Version 1.0.61
 - Use "route add -net" instead of "ip route add" when adding routes in 99.routing
 - lower the loglevel os several debug statements
 - check the status returned from ctdb_ctrl_get_tickles() before we try to print them out to the screen.
 - install a new eventscript 20.multipathd whoich can be used to monitor that multipath devices are healthy
* Wed Oct 15 2008 : Version 1.0.60
 - Verify that nodes we try to ban/unban are reachable and print an error othervise.
 - Update the client and server sides of TAKEIP/RELEASEIP/GETPUBLICIPS and GETNODEMAP to fall back to the old style ipv4-only controls if the new ipv4/ipv6 controls fail. This allows an ipv4/v6 enabled ctdb daemon to interoperate with earlier ipv4-only versions of the daemons.
 - From Mathieu Parent : log debian systems log the package versions in ctdb diagnostics
 - From Mathieu Parent : specify logdir location for debian (this patch was later reversed)
 - From Michael Adams : allow # comments in nodes/public_addresses files
* Tue Oct 7 2008 : Version 1.0.59
 - Updated "reloadnodes" logic. Instead of bouncing the entire tcp layer it is sufficient to just close and reopen all outgoing tcp connections.
 - New eventscript 99.routing which can be used to re-attach routes to public interfaces after a takeip event. (routes may be deleted by the kernel when we release an ip)
 - IDR tree fix from Jim Houston
 - Better handling of critical events if the local clock is suddenly changed forward by a lot.
 - Fix three slow memory leaks in the recovery daemon
 - New ctdb command : ctdb recmaster   which prints the pnn of the recmaster
 - Onnode enhancements from Martin S : "healthy" and "connected" are now possible nodespecifiers
 - From Martin S : doc fixes
 - lowering some debug levels for some nonvital informational messages
 - Make the daemon daemon monitoring stronger and allow ctdbd to detect a hung
   recovery daemon.
 - From C Cowan : patches to compile ipv6 under AIX
 - zero out some structs to keep valgrind happy
* Wed Aug 27 2008 : Version 1.0.58
 - revert the name change tcp_tcp_client back to tcp_control_tcp so
   samba can build.
 - Updates to the init script from Abhijith Das <adas@redhat.com>
* Mon Aug 25 2008 : Version 1.0.57
 - initial support for IPv6
* Mon Aug 11 2008 : Version 1.0.56
 - fix a memory leak in the recovery daemon.
* Mon Aug 11 2008 : Version 1.0.55
 - Fix the releaseip message we seond to samba.
* Fri Aug 8 2008 : Version 1.0.54
 - fix a looping error in the transaction code
 - provide a more detailed error code for persistent store errors
   so clients can make more intelligent choices on how to try to recover
* Thu Aug 7 2008 : Version 1.0.53
 - Remove the reclock.pnn file   it can cause gpfs to fail to umount
 - New transaction code
* Mon Aug 4 2008 : Version 1.0.52
 - Send an explicit gratious arp when starting sending the tcp tickles.
 - When doing failover, issue a killtcp to non-NFS/non-CIFS clients
   so that they fail quickly. NFS and CIFS already fail and recover 
   quickly.
 - Update the test scripts to handle CTRL-C to kill off the test.
* Mon Jul 28 2008 : Version 1.0.51
 - Strip off the vlan tag from bond devices before we check in /proc
   if the interface is up or not.
 - Use testparm in the background in the scripts to allow probing
   that the shares do exist.
 - Fix a bug in the logging code to handle multiline entries better
 - Rename private elements from private to private_data
* Fri Jul 18 2008 : Version 1.0.50
 - Dont assume that just because we can establish a TCP connection
   that we are actually talking to a functioning ctdb daemon.
   So dont mark the node as CONNECTED just because the tcp handshake
   was successful.
 - Dont try to set the recmaster to ourself during elections for those
   cases we know this will fail. To remove some annoying benign but scary
   looking entries from the log.
 - Bugfix for eventsystem for signal handling that could cause a node to
   hang.
* Thu Jul 17 2008 : Version 1.0.49
 - Update the safe persistent update fix to work with unpatched samba
   servers.
* Thu Jul 17 2008 : Version 1.0.48
 - Update the spec file.
 - Do not start new user-triggered eventscripts if we are already
   inside recovery mode.
 - Add two new controls to start/cancel a persistent update.
   A client such as samba can use these to tell ctdbd that it will soon
   be writing directly to the persistent database tdb file. So if
   samba is -9ed before it has eitehr done the persistent_store or
   canceled the operation, ctdb knows that the persistent databases
   'may' be out of sync and therefore a full blown recovery is called for.
 - Add two new options :
   CTDB_SAMBA_SKIP_CONF_CHECK and CTDB_SAMBA_CHECK_PORTS that can be used
   to override what checks to do when monitoring samba health.
   We can no longer use the smbstatus, net or testparm commands to check
   if samba or its config is healthy since these commands may block
   indefinitely and thus can not be used in scripts.
* Fri Jul 11 2008 : Version 1.0.47
 - Fix a double free bug where if a user striggered (ctdb eventscript)
   hung and while the timeout handler was being processed a new user
   triggered eventscript was started we would free state twice.
 - Rewrite of onnode and associated documentation.
* Thu Jul 10 2008 : Version 1.0.46
 - Document both the LVS:cingle-ip-address and the REMOTE-NODE:wan-accelerator
   capabilities.
 - Add commands "ctdb pnn", "ctdb lvs", "ctdb lvsmaster".
 - LVS improvements. LVS is the single-ip-address mode for a ctdb cluster.
 - Fixes to supress rpmlint warnings
 - AXI compile fixes.
 - Change \s to [[:space:]] in some scripts. Not all RHEL5 packages come
   with a egrep that handles \s   even same version but different arch.
 - Revert the change to NFS restart. CTDB should NOT attempt to restart
   failed services.
 - Rewrite of the waitpid() patch to use the eventsystem for handling
   signals.
* Tue Jul 8 2008 : Version 1.0.45
 - Try to restart the nfs service if it has failed to respond 3 times in a row.
 - waitpid() can block if the child does not respond promptly to SIGTERM.
   ignore all SIGCHILD signals by setting SIGCHLD to SIG_DEF.
   get rid of all calls to waitpid().
 - make handling of eventscripts hanging more liberal.
   only consider the script to have failed and making the node unhealthy
   IF the eventscript terminated wiht an error
   OR the eventscript hung 5 or more times in a row
* Mon Jul 7 2008 : Version 1.0.44
 - Add a CTDB_VALGRIND option to /etc/sysconfig/ctdb to make it start
   ctdb under valgrind. Logs go to /var/log/ctdb_valgrind.PID
 - Add a hack to show the control opcode that caused uninitialized data
   in the valgrind output by encoding the opcode as the line number.
 - Initialize structures and allocated memory in various places in
   ctdb to make it valgrind-clean and remove all valgrind errors/warnings.
 - If/when we destroy a lockwait child, also make sure we cancel any pending transactions
 - If a transaction_commit fails, delete/cancel any pending transactions and
   return an error instead of calling ctdb_fatal()
 - When running ctdb under valgrind, make sure we run it with --nosetsched and also
   ensure that we do not use mem-mapped i/o when accessing the tdb's.
 - zero out ctdb->freeze_handle when we free/destroy a freeze-child.
   This prevent a heap corruption/ctdb crash bug that could trigger
   if the freeze child times out.
 - we dont need to explicitely thaw the databases from the recovery daemon
   since this is done implicitely when we restore the recovery mode back to normal.
 - track when we start and stop a recovery. Add the 'time it took to complete the
   recovery' to the 'ctdb uptime' output.
   Ensure by tracking the start/stop recovery timestamps that we do not
   check that the ip allocation is consistend from inside the recovery daemon
   while a different node (recovery master) is performing a recovery.
   This prevent a race that could cause a full recovery to trigger if the
   'ctdb disable/enable' commands took very long.
 - The freeze child indicates to the master daemon that all databases are locked
   by writing data to the pipe shared with the master daemon.
   This write sometimes fail and thus the master daemon never notices that the databases
   are locked cvausing long timeouts and extra recoveries.
   Check that the write is successful and try the write again if it failed.
 - In each node, verify that the recmaster have the right node flags for us
   and force a push of our flags to the recmaster if wrong.
* Tue Jul 1 2008 : Version 1.0.43
 - Updates and bugfixes to the specfile to keep rpmlint happy
 - Force a global flags update after each recovery event.
 - Verify that the recmaster agrees with our node flags and update the
   recmaster othervise.
 - When writing back to the parent from a freeze-child across the pipe,
   loop over the write in case the write failed with an error  othervise
   the parent will never be notified tha the child has completed the operation.
 - Automatically thaw all databases when recmaster marks us as being in normal
   mode instead of recovery mode.
* Fri Jun 13 2008 : Version 1.0.42
 - When event scripts have hung/timedout more than EventScriptBanCount times
   in a row the node will ban itself.
 - Many updates to persistent write tests and the test scripts.
* Wed May 28 2008 : Version 1.0.41
 - Reactivate the safe writes to persistent databases and solve the
   locking issues. Locking issues are solved the only possible way,
   by using a child process to do the writes.  Expensive and slow but... . 
* Tue May 27 2008 : Version 1.0.40
 - Read the samba sysconfig file from the 50.samba eventscript
 - Fix some emmory hierarchical bugs in the persistent write handling
* Thu May 22 2008 : Version 1.0.39
 - Moved a CTDB_MANAGES_NFS, CTDB_MANAGES_ISCSI and CTDB_MANAGES_CSFTPD
   into /etc/sysconfig/ctdb
 - Lowered some debug messages to not fill the logfile with entries
   that normally occur in the default configuration.
* Fri May 16 2008 : Version 1.0.38
 - Add machine readable output support to "ctdb getmonmode"
 - Lots of tweaks and enhancements if the event scripts are "slow"
 - Merge from tridge: an attempt to break the chicken-and-egg deadlock that
   net conf introduces if used from an eventscript.
 - Enhance tickles so we can tickle an ipv6 connection.
 - Start adding ipv6 support : create a new container to replace sockaddr_in.
 - Add a checksum routine for ipv6/tcp
 - When starting up ctdb, let the init script do a tdbdump on all
   persistent databases and verify that they are good (i.e. not corrupted).
 - Try to use "safe transactions" when writing to a persistent database
   that was opened with the TDB_NOSYNC flag. If we can get the transaction
   thats great, if we cant  we have to write anyway since we cant block here.
* Mon May 12 2008 : Version 1.0.37
 - When we shutdown ctdb we close the transport down before we run the 
   "shutdown" eventscripts. If ctdb decides to send a packet to a remote node
   after we have shutdown the transport but before we have shutdown ctdbd
   itself this could lead to a SEGV instead of a clean shutdown. Fix.
 - When using the "exportfs" command to extract which NFS export directories
   to monitor,  exportfs violates the "principle of least surprise" and
   sometimes report a single export line as two lines of text output
   causing the monitoring to fail.
* Fri May 9 2008 : Version 1.0.36
 - fix a memory corruption bug that could cause the recovery daemon to crash.
 - fix a bug with distributing public ip addresses during recovery.
   If the node that is the recovery master did NOT use public addresses,
   then it assumed that no other node in the cluster used them either and
   thus skipped the entire step of reallocating public addresses.
* Wed May 7 2008 : Version 1.0.35
 - During recovery, when we define the new set of lmasters (vnnmap)
   only consider those nodes that have the can-be-lmaster capability
   when we create the vnnmap. unless there are no nodes available which
   supports this capability in which case we allow the recmaster to
   become lmaster capable (temporarily).
 - Extend the async framework so that we can use paralell async calls
   to controls that return data.
 - If we do not have the "can be recmaster" capability, make sure we will
   lose any recmaster elections, unless there are no nodes available that
   have the capability, in which case we "take/win" the election anyway.
 - Close and reopen the reclock pnn file at regular intervals.
   Make it a non-fatal event if we occasionally fail to open/read/write
   to this file.
 - Monitor that the recovery daemon is still running from the main ctdb
   daemon and shutdown the main daemon when recovery daemon has terminated.
 - Add a "ctdb getcapabilities" command to read the capabilities off a node.
 - Define two new capabilities : can be recmaster and can be lmaster
   and default both capabilities to YES.
 - Log denied tcp connection attempts with DEBUG_ERR and not DEBUG_WARNING
* Thu Apr 24 2008 : Version 1.0.34
 - When deleting a public ip from a node, try to migrate the ip to a different
   node first.
 - Change catdb to produce output similar to tdbdump
 - When adding a new public ip address, if this ip does not exist yet in
   the cluster, then grab the ip on the local node and activate it.
 - When a node disagrees with the recmaster on WHO is the recmaster, then
   mark that node as a recovery culprit so it will eventually become
   banned.
 - Make ctdb eventscript support the -n all argument.
* Thu Apr 10 2008 : Version 1.0.33
 - Add facilities to include site local adaptations to the eventscript
   by /etc/ctdb/rc.local which will be read by all eventscripts.
 - Add a "ctdb version" command.
 - Secure the domain socket with proper permissions from Chris Cowan
 - Bugfixes for AIX from Chris Cowan
* Wed Apr 02 2008 : Version 1.0.32
 - Add a control to have a node execute the eventscripts with arbitrary
   command line arguments.
 - Add a control "rddumpmemory" that will dump the talloc memory allocations
   for the recovery daemon.
 - Decorate the talloc memdump to produce better and easier memory leak
   tracking. 
 - Update the RHEL5 iscsi tgtd scripts to allow one iscsi target for each
   public address.
 - Add two new controls "addip/delip" that can be used to add/remove public
   addresses to a node at runtime. After using these controls a "ctdb recover"
   ir required to make the changes take.
 - Fix a couple of slow memory leaks.
* Tue Mar 25 2008 : Version 1.0.31
 - Add back controls to disable/enable monitoring on a node.
 - Fix a memory leak where we used to attach CALL data to the ctdb structure
   when performing a local call. Memory which would be lost if the call was
   aborted.
 - Reduce the loglevel for the log output when someone connects to a non
   public ip address for samba.
 - Redo and optimize the vacuuming process to send only one control to each
   other node containing all records to be vacuumed instead of one
   control per node per record.
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
