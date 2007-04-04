#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

package Samba3;

use strict;
use FindBin qw($RealBin);
use POSIX;

sub new($$$) {
	my ($classname, $bindir, $setupdir) = @_;
	my $self = { bindir => $bindir, setupdir => $setupdir };
	bless $self;
	return $self;
}

sub check_or_start($$$$) 
{
	my ($self, $env_vars, $socket_wrapper_dir, $max_time) = @_;
	return 0 if ( -p $env_vars->{SMBD_TEST_FIFO});

	warn("Not using socket wrapper, but also not running as root. Will not be able to listen on proper ports") unless
		defined($socket_wrapper_dir) or $< == 0;

	unlink($env_vars->{SMBD_TEST_FIFO});
	POSIX::mkfifo($env_vars->{SMBD_TEST_FIFO}, 0700);
	unlink($env_vars->{SMBD_TEST_LOG});
	
	my $valgrind = "";
	if (defined($ENV{SMBD_VALGRIND})) {
		$valgrind = $ENV{SMBD_VALGRIND};
	} 

	print "STARTING SMBD... ";
	my $pid = fork();
	if ($pid == 0) {
		open STDIN, $env_vars->{SMBD_TEST_FIFO};
		open STDOUT, ">$env_vars->{SMBD_TEST_LOG}";
		open STDERR, '>&STDOUT';
		my $optarg = "";
		if (defined($max_time)) {
			$optarg = "--maximum-runtime=$max_time ";
		}
		my $ret = system("$valgrind $self->{bindir}/smbd $optarg -s $env_vars->{CONFFILE} -M single -i --leak-report-full");
		if ($? == -1) {
			print "Unable to start smbd: $ret: $!\n";
			exit 1;
		}
		unlink($env_vars->{SMBD_TEST_FIFO});
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

	open(DATA, ">$env_vars->{SMBD_TEST_FIFO}");

	return $pid;
}

sub wait_for_start($)
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

sub provision($$$)
{
	my ($self, $environment, $prefix) = @_;
	my %ret = ();
	print "PROVISIONING...";
	open(IN, "$RealBin/mktestdc.sh $prefix|") or die("Unable to setup");
	while (<IN>) {
		die ("Error parsing `$_'") unless (/^([A-Z0-9a-z_]+)=(.*)$/);
		$ret{$1} = $2;
	}
	close(IN);

	$ret{SMBD_TEST_FIFO} = "$prefix/smbd_test.fifo";
	$ret{SMBD_TEST_LOG} = "$prefix/smbd_test.log";
	return \%ret;
}

sub stop($)
{
	my ($self) = @_;

	close(DATA);

	sleep(2);

	my $failed = $? >> 8;

	if (-f "$ENV{PIDDIR}/smbd.pid" ) {
		open(IN, "<$ENV{PIDDIR}/smbd.pid") or die("unable to open smbd pid file");
		kill 9, <IN>;
		close(IN);
	}

	return $failed;
}

sub setup_env($$$)
{
	my ($self, $name, $socket_wrapper_dir) = @_;
}

1;
