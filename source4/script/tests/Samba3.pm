#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

package Samba3;

use strict;
use Cwd qw(abs_path);
use FindBin qw($RealBin);
use POSIX;

sub binpath($$)
{
	my ($self, $binary) = @_;

	if (defined($self->{bindir})) {
		my $path = "$self->{bindir}/$binary";
		-f $path or die("File $path doesn't exist");
		return $path;
	}

	return $binary;
}

sub new($$) {
	my ($classname, $bindir) = @_;
	my $self = { bindir => $bindir };
	bless $self;
	return $self;
}

sub teardown_env($$)
{
	my ($self, $envvars) = @_;

	$self->samba3_stop_sig_term($envvars->{PIDDIR});
	$self->samba3_stop_sig_kill($envvars->{PIDDIR});

	return 0;
}

sub getlog_env($$)
{
	my ($self, $envvars) = @_;

	# TODO...
	return "";
}

sub check_env($$)
{
	my ($self, $envvars) = @_;

	# TODO ...
	return 1;
}

sub setup_env($$$)
{
	my ($self, $envname, $path) = @_;
	
	if ($envname eq "dc") {
		return $self->setup_dc("$path/dc");
	} else {
		die("Samba4 can't provide environment '$envname'");
	}
}

sub setup_dc($$)
{
	my ($self, $path) = @_;

	my $vars = $self->provision($path);

	$self->check_or_start($vars, ($ENV{NMBD_MAXTIME} or 2700), ($ENV{SMBD_MAXTIME} or 2700));

	$self->wait_for_start($vars);

	return $vars;
}

sub stop($)
{
	my ($self) = @_;
}

sub samba3_stop_sig_term($$) {
	my ($self, $piddir) = @_;
	my $ret = 0;
	kill("USR1", `cat $piddir/timelimit.nmbd.pid`) or \
		kill("ALRM", `cat $piddir/timelimit.nmbd.pid`) or $ret++;

	kill("USR1", `cat $piddir/timelimit.smbd.pid`) or \
		kill("ALRM", `cat $piddir/timelimit.smbd.pid`) or $ret++;

	return $ret;
}

sub samba3_stop_sig_kill($$) {
	my ($self, $piddir) = @_;
	kill("ALRM", `cat $piddir/timelimit.nmbd.pid`); 
	kill("ALRM", `cat $piddir/timelimit.smbd.pid`);
	return 0;
}

sub check_or_start($$$$) {
	my ($self, $env_vars, $nmbd_maxtime, $smbd_maxtime) = @_;

	unlink($env_vars->{NMBD_TEST_LOG});
	print "STARTING NMBD...";
	my $pid = fork();
	if ($pid == 0) {
		open STDOUT, ">$env_vars->{NMBD_TEST_LOG}";
		open STDERR, '>&STDOUT';
	
		$ENV{MAKE_TEST_BINARY} = $self->binpath("nmbd");
		exec($self->binpath("timelimit"), $nmbd_maxtime, $self->binpath("nmbd"), "-F", "-S", "--no-process-group", "-d0" ,"-s", $env_vars->{SERVERCONFFILE}) or die("Unable to start nmbd: $!");
	}
	open(PID, ">$env_vars->{PIDDIR}/timelimit.nmbd.pid");
	print PID $pid;
	close(PID);
	print "DONE\n";

	unlink($env_vars->{SMBD_TEST_LOG});
	print "STARTING SMBD...";
	$pid = fork();
	if ($pid == 0) {
		open STDOUT, ">$env_vars->{SMBD_TEST_LOG}";
		open STDERR, '>&STDOUT';
	
		$ENV{MAKE_TEST_BINARY} = $self->binpath("smbd");
		exec($self->binpath("timelimit"), $nmbd_maxtime, $self->binpath("smbd"), "-F", "-S", "--no-process-group", "-d0" ,"-s", $env_vars->{SERVERCONFFILE}) or die("Unable to start smbd: $!");
	}
	open(PID, ">$env_vars->{PIDDIR}/timelimit.smbd.pid");
	print PID $pid;
	close(PID);
	print "DONE\n";

	return 0;
}

sub create_clientconf($$$)
{
	my ($self, $prefix, $domain) = @_;

	my $lockdir = "$prefix/locks";
	my $logdir = "$prefix/logs";
	my $piddir = "$prefix/pid";
	my $privatedir = "$prefix/private";
	my $scriptdir = "$RealBin/..";
	my $conffile = "$prefix/smb.conf";

	my $torture_interfaces='127.0.0.6/8,127.0.0.7/8,127.0.0.8/8,127.0.0.9/8,127.0.0.10/8,127.0.0.11/8';
	open(CONF, ">$conffile");
	print CONF "
[global]
	workgroup = $domain

	private dir = $privatedir
	pid directory = $piddir
	lock directory = $lockdir
	log file = $logdir/log.\%m
	log level = 0

	name resolve order = bcast

	netbios name = TORTURE_6
	interfaces = $torture_interfaces
	panic action = $scriptdir/gdb_backtrace \%d %\$(MAKE_TEST_BINARY)

	passdb backend = tdbsam
	";
	close(CONF);
}

sub provision($$)
{
	my ($self, $prefix) = @_;

	##
	## setup the various environment variables we need
	##

	my %ret = ();
	my $server = "localhost2";
	my $server_ip = "127.0.0.2";
	my $username = `PATH=/usr/ucb:$ENV{PATH} whoami`;
	my $password = "test";

	my $srcdir="$RealBin/../..";
	my $scriptdir="$srcdir/script/tests";
	my $prefix_abs = abs_path($prefix);
	my $shrdir="$prefix_abs/tmp";
	my $libdir="$prefix_abs/lib";
	my $piddir="$prefix_abs/pid";
	my $conffile="$libdir/server.conf";
	my $privatedir="$prefix_abs/private";
	my $lockdir="$prefix_abs/lockdir";
	my $logdir="$prefix_abs/logs";
	my $domain = "SAMBA-TEST";

	## 
	## create the test directory layout
	##
	mkdir($prefix_abs);
	print "CREATE TEST ENVIRONMENT IN '$prefix'...";
	system("rm -rf $prefix_abs/*");
	mkdir($_) foreach($privatedir,$libdir,$piddir,$lockdir,$logdir);
	my $tmpdir = "$prefix_abs/tmp";
	mkdir($tmpdir);
	chmod 0777, $tmpdir;

	open(CONF, ">$conffile") or die("Unable to open $conffile");
	print CONF "
[global]
	workgroup = $domain

	private dir = $privatedir
	pid directory = $piddir
	lock directory = $lockdir
	log file = $logdir/log.\%m
	log level = 0

	name resolve order = bcast

	netbios name = $server
	interfaces = $server_ip/8
	bind interfaces only = yes
	panic action = $scriptdir/gdb_backtrace %d %\$(MAKE_TEST_BINARY)

	passdb backend = tdbsam

	; Necessary to add the build farm hacks
	add user script = /bin/false
	add machine script = /bin/false

	kernel oplocks = no
	kernel change notify = no

	syslog = no
	printing = bsd
	printcap name = /dev/null

[tmp]
	path = $tmpdir
	read only = no
	smbd:sharedelay = 100000
	map hidden = yes
	map system = yes
	create mask = 755
[hideunread]
	copy = tmp
	hide unreadable = yes
[hideunwrite]
	copy = tmp
	hide unwriteable files = yes
[print1]
	copy = tmp
	printable = yes
	printing = test
[print2]
	copy = print1
[print3]
	copy = print1
[print4]
	copy = print1
	";
	close(CONF);

	##
	## create a test account
	##

	open(PWD, "|".$self->binpath("smbpasswd")." -c $conffile -L -s -a $username");
	print PWD "$password\n$password\n";
	close(PWD) or die("Unable to set password for test account");

	print "DONE\n";

	$ret{SERVER_IP} = $server_ip;
	$ret{NMBD_TEST_LOG} = "$prefix/nmbd_test.log";
	$ret{SMBD_TEST_LOG} = "$prefix/smbd_test.log";
	$ret{SERVERCONFFILE} = $conffile;
	$ret{CONFIGURATION} ="-s $conffile";
	$ret{SERVER} = $server;
	$ret{USERNAME} = $username;
	$ret{DOMAIN} = $domain;
	$ret{NETBIOSNAME} = $server;
	$ret{PASSWORD} = $password;
	$ret{PIDDIR} = $piddir;
	return \%ret;
}

sub wait_for_start($$)
{
	my ($self, $envvars) = @_;

	# give time for nbt server to register its names
	print "delaying for nbt name registration\n";
	sleep(10);
	# This will return quickly when things are up, but be slow if we need to wait for (eg) SSL init 
	system($self->binpath("nmblookup") ." $envvars->{CONFIGURATION} -U $envvars->{SERVER_IP} __SAMBA__");
	system($self->binpath("nmblookup") ." $envvars->{CONFIGURATION} __SAMBA__");
	system($self->binpath("nmblookup") ." $envvars->{CONFIGURATION} -U 127.255.255.255 __SAMBA__");
	system($self->binpath("nmblookup") ." $envvars->{CONFIGURATION} -U $envvars->{SERVER_IP} $envvars->{SERVER}");
	system($self->binpath("nmblookup") ." $envvars->{CONFIGURATION} $envvars->{SERVER}");
	# make sure smbd is also up set
	print "wait for smbd\n";
	system($self->binpath("smbclient") ." $envvars->{CONFIGURATION} -L $envvars->{SERVER_IP} -U% -p 139 | head -2");
	system($self->binpath("smbclient") ." $envvars->{CONFIGURATION} -L $envvars->{SERVER_IP} -U% -p 139 | head -2");

	print $self->getlog_env($envvars);
}

1;
