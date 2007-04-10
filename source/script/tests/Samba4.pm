#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

package Samba4;

use strict;
use FindBin qw($RealBin);
use POSIX;

sub new($$$$) {
	my ($classname, $bindir, $ldap, $setupdir) = @_;
	my $self = { ldap => $ldap, bindir => $bindir, setupdir => $setupdir };
	bless $self;
	return $self;
}

sub slapd_start($$)
{
    my $count = 0;
	my ($self, $env_vars) = @_;

	my $conf = $env_vars->{SLAPD_CONF};
	my $uri = $env_vars->{LDAP_URI};

	# running slapd in the background means it stays in the same process group, so it can be
	# killed by timelimit
	if (defined($ENV{FEDORA_DS_PREFIX})) {
	        system("$ENV{FEDORA_DS_PREFIX}/sbin/ns-slapd -D $ENV{FEDORA_DS_DIR} -d$ENV{FEDORA_DS_LOGLEVEL} -i $ENV{FEDORA_DS_PIDFILE}> $ENV{LDAPDIR}/logs 2>&1 &");
	} else {
		my $oldpath = $ENV{PATH};
		$ENV{PATH} = "/usr/local/sbin:/usr/sbin:/sbin:$ENV{PATH}";
		system("slapd -d$ENV{OPENLDAP_LOGLEVEL} -f $conf -h $uri > $ENV{LDAPDIR}/logs 2>&1 &");
		$ENV{PATH} = $oldpath;
	}
	while (system("$self->{bindir}/ldbsearch -H $uri -s base -b \"\" supportedLDAPVersion > /dev/null") != 0) {
	        $count++;
		if ($count > 10) {
		    $self->slapd_stop($env_vars);
		    return 0;
		}
		sleep(1);
	}
	return 1;
}

sub slapd_stop($$)
{
	my ($self, $envvars) = @_;
	if (defined($envvars->{FEDORA_DS_PREFIX})) {
		system("$envvars->{LDAPDIR}/slapd-samba4/stop-slapd");
	} else {
		open(IN, "<$envvars->{PIDDIR}/slapd.pid") or 
			die("unable to open slapd pid file");
		kill 9, <IN>;
		close(IN);
	}
}

sub check_or_start($$$$) 
{
	my ($self, $env_vars, $socket_wrapper_dir, $max_time) = @_;
	return 0 if ( -p $env_vars->{SMBD_TEST_FIFO});

	# Start slapd before smbd
	if ($self->{ldap}) {
		$self->slapd_start($env_vars) or 
			die("couldn't start slapd");

		print "LDAP PROVISIONING...";
		$self->provision_ldap();
	}

	SocketWrapper::set_default_iface(1);

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

sub wait_for_start($$)
{
	my ($self, $testenv_vars) = @_;
	# give time for nbt server to register its names
	print "delaying for nbt name registration\n";

	# This will return quickly when things are up, but be slow if we 
	# need to wait for (eg) SSL init 
	system("bin/nmblookup $testenv_vars->{CONFIGURATION} $testenv_vars->{SERVER}");
	system("bin/nmblookup $testenv_vars->{CONFIGURATION} -U $testenv_vars->{SERVER} $testenv_vars->{SERVER}");
	system("bin/nmblookup $testenv_vars->{CONFIGURATION} $testenv_vars->{SERVER}");
	system("bin/nmblookup $testenv_vars->{CONFIGURATION} -U $testenv_vars->{SERVER} $testenv_vars->{NETBIOSNAME}");
	system("bin/nmblookup $testenv_vars->{CONFIGURATION} $testenv_vars->{NETBIOSNAME}");
	system("bin/nmblookup $testenv_vars->{CONFIGURATION} -U $testenv_vars->{SERVER} $testenv_vars->{NETBIOSNAME}");
	system("bin/nmblookup $testenv_vars->{CONFIGURATION} $testenv_vars->{NETBIOSNAME}");
	system("bin/nmblookup $testenv_vars->{CONFIGURATION} -U $testenv_vars->{SERVER} $testenv_vars->{NETBIOSNAME}");
}

sub provision($$)
{
	my ($self, $prefix) = @_;
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

sub provision_ldap($)
{
	my ($self) = @_;
    system("$self->{bindir}/smbscript $self->{setupdir}/provision $ENV{PROVISION_OPTIONS} \"$ENV{PROVISION_ACI}\" --ldap-backend=$ENV{LDAP_URI}") and
		die("LDAP PROVISIONING failed: $self->{bindir}/smbscript $self->{setupdir}/provision $ENV{PROVISION_OPTIONS} \"$ENV{PROVISION_ACI}\" --ldap-backend=$ENV{LDAP_URI}");
}

sub teardown_env($$)
{
	my ($self, $envvars) = @_;

	close(DATA);

	sleep(2);

	my $failed = $? >> 8;

	if (-f "$envvars->{PIDDIR}/smbd.pid" ) {
		open(IN, "<$envvars->{PIDDIR}/smbd.pid") or die("unable to open smbd pid file");
		kill 9, <IN>;
		close(IN);
	}

	$self->slapd_stop($envvars) if ($self->{ldap});

	return $failed;
}

sub setup_env($$$$)
{
	my ($self, $envname, $path, $socket_wrapper_dir) = @_;
	
	if ($envname eq "dc") {
		return $self->setup_dc("$path/dc", $socket_wrapper_dir);
	} else {
		die("Samba4 can't provide environment $envname");
	}
}

sub setup_dc($$$)
{
	my ($self, $path, $socket_wrapper_dir) = @_;

	my $env = $self->provision($path);

	$self->check_or_start($env, $socket_wrapper_dir, 
		($ENV{SMBD_MAX_TIME} or 5400));

	$self->wait_for_start($env);

	return $env;
}

sub stop($)
{
	my ($self) = @_;
}

1;
