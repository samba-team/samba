#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

package Samba4;

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(slapd_start slapd_stop smbd_check_or_start provision);

use strict;
use FindBin qw($RealBin);
use POSIX;

sub slapd_start($$$)
{
        my $count = 0;
	my ($bindir, $conf, $uri) = @_;
	# running slapd in the background means it stays in the same process group, so it can be
	# killed by timelimit
	if (defined($ENV{FEDORA_DS_PREFIX})) {
	        system("$ENV{FEDORA_DS_PREFIX}/sbin/ns-slapd -D $ENV{FEDORA_DS_DIR} -d$ENV{FEDORA_DS_LOGLEVEL} > $ENV{LDAPDIR}/logs 2>&1 &");
	} else {
		my $oldpath = $ENV{PATH};
		$ENV{PATH} = "/usr/local/sbin:/usr/sbin:/sbin:$ENV{PATH}";
		system("slapd -d$ENV{OPENLDAP_LOGLEVEL} -f $conf -h $uri > $ENV{LDAPDIR}/logs 2>&1 &");
		$ENV{PATH} = $oldpath;
	}
	while (system("$bindir/ldbsearch -H $uri -s base -b \"\" supportedLDAPVersion > /dev/null") != 0) {
	        $count++;
		if ($count > 10) {
		    slapd_stop();
		    return 0;
		}
		sleep(1);
	}
	return 1;
}

sub slapd_stop()
{
	if (defined($ENV{FEDORA_DS_PREFIX})) {
		system("$ENV{LDAPDIR}/slapd-samba4/stop-slapd");
	} else {
		open(IN, "<$ENV{PIDDIR}/slapd.pid") or 
			die("unable to open slapd pid file");
		kill 9, <IN>;
		close(IN);
	}
}

sub smbd_check_or_start($$$$$$) 
{
	my ($bindir, $test_fifo, $test_log, $socket_wrapper_dir, $max_time, $conffile) = @_;
	return 0 if ( -p $test_fifo );

	warn("Not using socket wrapper, but also not running as root. Will not be able to listen on proper ports") unless
		defined($socket_wrapper_dir) or $< == 0;

	unlink($test_fifo);
	POSIX::mkfifo($test_fifo, 0700);
	unlink($test_log);
	
	my $valgrind = "";
	if (defined($ENV{SMBD_VALGRIND})) {
		$valgrind = $ENV{SMBD_VALGRIND};
	} 

	print "STARTING SMBD...";
	my $pid = fork();
	if ($pid == 0) {
		open STDIN, $test_fifo;
		open STDOUT, ">$test_log";
		open STDERR, '>&STDOUT';
		my $optarg = "";
		if (defined($max_time)) {
			$optarg = "--maximum-runtime=$max_time ";
		}
		my $ret = system("$valgrind $bindir/smbd $optarg -s $conffile -M single -i --leak-report-full");
		if ($? == -1) {
			print "Unable to start smbd: $ret: $!\n";
			exit 1;
		}
		unlink($test_fifo);
		unlink(<$socket_wrapper_dir/*>) if (defined($socket_wrapper_dir) and -d $socket_wrapper_dir);
		my $exit = $? >> 8;
		if ( $ret == 0 ) {
			print "smbd exits with status $exit\n";
		} elsif ( $ret & 127 ) {
			print "smbd got signal ".($ret & 127)." and exits with $exit!\n";
		} else {
			$ret = $? >> 8;
			print "smbd failed with status $exit!\n";
		}
		exit $exit;
	}
	print "DONE\n";

	return $pid;
}

sub wait_for_start()
{
	# give time for nbt server to register its names
	print "delaying for nbt name registration\n";

	# This will return quickly when things are up, but be slow if we 
	# need to wait for (eg) SSL init 
	system("bin/nmblookup $ENV{CONFIGURATION} $ENV{SERVER}");
	system("bin/nmblookup $ENV{CONFIGURATION} -U $ENV{SERVER} $ENV{SERVER}");
	system("bin/nmblookup $ENV{CONFIGURATION} $ENV{SERVER}");
	system("bin/nmblookup $ENV{CONFIGURATION} -U $ENV{SERVER} $ENV{NETBIOSNAME}");
	system("bin/nmblookup $ENV{CONFIGURATION} $ENV{NETBIOSNAME}");
	system("bin/nmblookup $ENV{CONFIGURATION} -U $ENV{SERVER} $ENV{NETBIOSNAME}");
	system("bin/nmblookup $ENV{CONFIGURATION} $ENV{NETBIOSNAME}");
	system("bin/nmblookup $ENV{CONFIGURATION} -U $ENV{SERVER} $ENV{NETBIOSNAME}");
}

sub provision($)
{
	my ($prefix) = @_;
	my %ret = ();
	print "PROVISIONING...";
	open(IN, "$RealBin/mktestsetup.sh $prefix|") or die("Unable to setup");
	while (<IN>) {
		die ("Error parsing `$_'") unless (/^([A-Z0-9a-z_]+)=(.*)$/);
		$ret{$1} = $2;
	}
	close(IN);
	return \%ret;
}

sub provision_ldap($$)
{
	my ($bindir, $setupdir) = @_;
    system("$bindir/smbscript $setupdir/provision $ENV{PROVISION_OPTIONS} \"$ENV{PROVISION_ACI}\" --ldap-backend=$ENV{LDAP_URI}") and
		die("LDAP PROVISIONING failed: $bindir/smbscript $setupdir/provision $ENV{PROVISION_OPTIONS} \"$ENV{PROVISION_ACI}\" --ldap-backend=$ENV{LDAP_URI}");
}

1;
