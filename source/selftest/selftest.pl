#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

=pod

=head1 NAME

selftest - Samba test runner

=head1 SYNOPSIS

selftest --help

selftest [--srcdir=DIR] [--builddir=DIR] [--target=samba4|samba3|win] [--socket-wrapper] [--quick] [--one] [--prefix=prefix] [--immediate] [TESTS]

=head1 DESCRIPTION

A simple test runner. TESTS is a regular expression with tests to run.

=head1 OPTIONS

=over 4

=item I<--help>

Show list of available options.

=item I<--srcdir=DIR>

Source directory.

=item I<--builddir=DIR>

Build directory.

=item I<--prefix=DIR>

Change directory to run tests in. Default is 'st'.

=item I<--immediate>

Show errors as soon as they happen rather than at the end of the test run.
		
=item I<--target samba4|samba3|win>

Specify test target against which to run. Default is 'samba4'.

=item I<--quick>

Run only a limited number of tests. Intended to run in about 30 seconds on 
moderately recent systems.
		
=item I<--socket-wrapper>

Use socket wrapper library for communication with server. Only works 
when the server is running locally.

Will prevent TCP and UDP ports being opened on the local host but 
(transparently) redirects these calls to use unix domain sockets.

=item I<--expected-failures>

Specify a file containing a list of tests that are expected to fail. Failures for 
these tests will be counted as successes, successes will be counted as failures.

The format for the file is, one entry per line:

TESTSUITE-NAME/TEST-NAME

=item I<--skip>

Specify a file containing a list of tests that should be skipped. Possible candidates are
tests that segfault the server, flip or don't end.

=item I<--one>

Abort as soon as one test fails.

=back

=head1 ENVIRONMENT

=over 4

=item I<SMBD_VALGRIND>

=item I<TORTURE_MAXTIME>

=item I<VALGRIND>

=item I<TLS_ENABLED>

=item I<srcdir>

=back

=head1 LICENSE

selftest is licensed under the GNU General Public License L<http://www.gnu.org/licenses/gpl.html>.

=head1 AUTHOR

Jelmer Vernooij

=cut

use strict;

use FindBin qw($RealBin $Script);
use File::Spec;
use Getopt::Long;
use POSIX;
use Cwd qw(abs_path);
use lib "$RealBin";
use Subunit qw(parse_results);
use env::Samba3;
use env::Samba4;
use env::Windows;
use SocketWrapper;

my $opt_help = 0;
my $opt_target = "samba4";
my $opt_quick = 0;
my $opt_socket_wrapper = 0;
my $opt_socket_wrapper_pcap = undef;
my $opt_socket_wrapper_keep_pcap = undef;
my $opt_one = 0;
my $opt_immediate = 0;
my $opt_expected_failures = undef;
my $opt_skip = undef;
my $opt_verbose = 0;
my $opt_testenv = 0;
my $ldap = undef;
my $opt_analyse_cmd = undef;
my $opt_resetup_env = undef;
my $opt_bindir = undef;
my $opt_no_lazy_setup = undef;
my $opt_format = "plain";

my $srcdir = ".";
my $builddir = ".";
my $prefix = "./st";

my @expected_failures = ();
my @skips = ();

my $statistics = {
	START_TIME => time(),

	SUITES_FAIL => 0,
	SUITES_OK => 0,
	SUITES_SKIPPED => 0,

	TESTS_UNEXPECTED_OK => 0,
	TESTS_EXPECTED_OK => 0,
	TESTS_UNEXPECTED_FAIL => 0,
	TESTS_EXPECTED_FAIL => 0,
	TESTS_ERROR => 0,
	TESTS_SKIP => 0,
};

sub expecting_failure($)
{
	my $fullname = shift;

	foreach (@expected_failures) {
		return 1 if ($fullname =~ /$_/);
	}

	return 0;
}

sub skip($)
{
	my $fullname = shift;

	foreach (@skips) {
		return 1 if ($fullname =~ /$_/);
	}

	return 0;
}

sub getlog_env($);

sub setup_pcap($)
{
	my ($state) = @_;

	return unless ($opt_socket_wrapper_pcap);
	return unless defined($ENV{SOCKET_WRAPPER_PCAP_DIR});

	my $fname = sprintf("t%03u_%s", $state->{INDEX}, $state->{NAME});
	$fname =~ s%[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\-]%_%g;

	$state->{PCAP_FILE} = "$ENV{SOCKET_WRAPPER_PCAP_DIR}/$fname.pcap";

	SocketWrapper::setup_pcap($state->{PCAP_FILE});
}

sub cleanup_pcap($$$)
{
	my ($state, $expected_ret, $ret) = @_;

	return unless ($opt_socket_wrapper_pcap);
	return if ($opt_socket_wrapper_keep_pcap);
	return unless ($expected_ret == $ret);
	return unless defined($state->{PCAP_FILE});

	unlink($state->{PCAP_FILE});
	$state->{PCAP_FILE} = undef;
}

sub run_testsuite($$$$$$)
{
	my ($envname, $name, $cmd, $i, $totalsuites, $msg_ops) = @_;
	my $msg_state = {
		ENVNAME	=> $envname,
		NAME	=> $name,
		CMD	=> $cmd,
		INDEX	=> $i,
		TOTAL	=> $totalsuites,
		START_TIME	=> time()
	};

	setup_pcap($msg_state);

	open(RESULT, "$cmd 2>&1|");
	$msg_ops->start_testsuite($msg_state);

	my $expected_ret = parse_results(
		$msg_ops, $msg_state, $statistics, *RESULT, \&expecting_failure);

	my $ret = close(RESULT);

	cleanup_pcap($msg_state, $expected_ret, $ret);

	$msg_ops->end_testsuite($msg_state, $expected_ret, $ret,
							getlog_env($msg_state->{ENVNAME}));

	if (not $opt_socket_wrapper_keep_pcap and 
		defined($msg_state->{PCAP_FILE})) {
		$msg_ops->output_msg($msg_state, 
			"PCAP FILE: $msg_state->{PCAP_FILE}\n");
	}

	if ($ret != $expected_ret) {
		$statistics->{SUITES_FAIL}++;
		exit(1) if ($opt_one);
	} else {
		$statistics->{SUITES_OK}++;
	}

	return ($ret == $expected_ret);
}

sub ShowHelp()
{
	print "Samba test runner
Copyright (C) Jelmer Vernooij <jelmer\@samba.org>

Usage: $Script [OPTIONS] PREFIX

Generic options:
 --help                     this help page
 --target=samba4|samba3|win Samba version to target

Paths:
 --prefix=DIR               prefix to run tests in [st]
 --srcdir=DIR               source directory [.]
 --builddir=DIR             output directory [.]

Target Specific:
 --socket-wrapper-pcap=DIR	save traffic to pcap directories
 --socket-wrapper-keep-pcap keep all pcap files, not just those for tests that 
                            failed
 --socket-wrapper           enable socket wrapper
 --expected-failures=FILE   specify list of tests that is guaranteed to fail

Samba4 Specific:
 --ldap=openldap|fedora-ds     back smbd onto specified ldap server

Samba3 Specific:
 --bindir=PATH              path to binaries

Behaviour:
 --quick                    run quick overall test
 --one                      abort when the first test fails
 --immediate                print test output for failed tests during run
 --verbose                  be verbose
 --analyse-cmd CMD          command to run after each test
";
	exit(0);
}

my $result = GetOptions (
		'help|h|?' => \$opt_help,
		'target=s' => \$opt_target,
		'prefix=s' => \$prefix,
		'socket-wrapper' => \$opt_socket_wrapper,
		'socket-wrapper-pcap' => \$opt_socket_wrapper_pcap,
		'socket-wrapper-keep-pcap' => \$opt_socket_wrapper_keep_pcap,
		'quick' => \$opt_quick,
		'one' => \$opt_one,
		'immediate' => \$opt_immediate,
		'expected-failures=s' => \$opt_expected_failures,
		'skip=s' => \$opt_skip,
		'srcdir=s' => \$srcdir,
		'builddir=s' => \$builddir,
		'verbose' => \$opt_verbose,
		'testenv' => \$opt_testenv,
		'ldap:s' => \$ldap,
		'analyse-cmd=s' => \$opt_analyse_cmd,
		'no-lazy-setup' => \$opt_no_lazy_setup,
		'resetup-environment' => \$opt_resetup_env,
		'bindir:s' => \$opt_bindir,
		'format=s' => \$opt_format,
	    );

exit(1) if (not $result);

ShowHelp() if ($opt_help);

my $tests = shift;

# quick hack to disable rpc validation when using valgrind - its way too slow
unless (defined($ENV{VALGRIND})) {
	$ENV{VALIDATE} = "validate";
	$ENV{MALLOC_CHECK_} = 2;
}

my $old_pwd = "$RealBin/..";

# Backwards compatibility:
if (defined($ENV{TEST_LDAP}) and $ENV{TEST_LDAP} eq "yes") {
	if (defined($ENV{FEDORA_DS_PREFIX})) {
		$ldap = "fedora-ds";
	} else {
		$ldap = "openldap";
	}
}

my $torture_maxtime = ($ENV{TORTURE_MAXTIME} or 1200);
if ($ldap) {
	# LDAP is slow
	$torture_maxtime *= 2;
}

$prefix =~ s+//+/+;
$prefix =~ s+/./+/+;
$prefix =~ s+/$++;

die("using an empty prefix isn't allowed") unless $prefix ne "";

#Ensure we have the test prefix around
mkdir($prefix, 0777) unless -d $prefix;

my $prefix_abs = abs_path($prefix);
my $srcdir_abs = abs_path($srcdir);

die("using an empty absolute prefix isn't allowed") unless $prefix_abs ne "";
die("using '/' as absolute prefix isn't allowed") unless $prefix_abs ne "/";

$ENV{PREFIX} = $prefix;
$ENV{PREFIX_ABS} = $prefix_abs;
$ENV{SRCDIR} = $srcdir;
$ENV{SRCDIR_ABS} = $srcdir_abs;

my $tls_enabled = not $opt_quick;
if (defined($ENV{RUN_FROM_BUILD_FARM}) and 
	($ENV{RUN_FROM_BUILD_FARM} eq "yes")) {
	$opt_format = "buildfarm";
}

$ENV{TLS_ENABLED} = ($tls_enabled?"yes":"no");
$ENV{LD_LDB_MODULE_PATH} = "$old_pwd/bin/modules/ldb";
$ENV{LD_SAMBA_MODULE_PATH} = "$old_pwd/bin/modules";
if (defined($ENV{LD_LIBRARY_PATH})) {
	$ENV{LD_LIBRARY_PATH} = "$old_pwd/bin/shared:$ENV{LD_LIBRARY_PATH}";
} else {
	$ENV{LD_LIBRARY_PATH} = "$old_pwd/bin/shared";
}
if (defined($ENV{PKG_CONFIG_PATH})) {
	$ENV{PKG_CONFIG_PATH} = "$old_pwd/bin/pkgconfig:$ENV{PKG_CONFIG_PATH}";
} else { 
	$ENV{PKG_CONFIG_PATH} = "$old_pwd/bin/pkgconfig";
}
$ENV{PATH} = "$old_pwd/bin:$ENV{PATH}";


if ($opt_socket_wrapper_pcap) {
	# Socket wrapper pcap implies socket wrapper
	$opt_socket_wrapper = 1;
}

my $socket_wrapper_dir;
if ($opt_socket_wrapper) {
	$socket_wrapper_dir = SocketWrapper::setup_dir("$prefix/w", $opt_socket_wrapper_pcap);
	print "SOCKET_WRAPPER_DIR=$socket_wrapper_dir\n";
} else {
	warn("Not using socket wrapper, but also not running as root. Will not be able to listen on proper ports") unless $< == 0;
}

my $target;

if ($opt_target eq "samba4") {
	$target = new Samba4("$srcdir/bin", $ldap, "$srcdir/setup");
} elsif ($opt_target eq "samba3") {
	if ($opt_socket_wrapper and `smbd -b | grep SOCKET_WRAPPER` eq "") {
		die("You must include --enable-socket-wrapper when compiling Samba in order to execute 'make test'.  Exiting....");
	}

	$target = new Samba3($opt_bindir);
} elsif ($opt_target eq "win") {
	die("Windows tests will not run with socket wrapper enabled.") 
		if ($opt_socket_wrapper);
	$target = new Windows();
}

if (defined($opt_expected_failures)) {
	open(KNOWN, "<$opt_expected_failures") or die("unable to read known failures file: $!");
	while (<KNOWN>) { 
		chomp; 
		s/([ \t]+)\#(.*)$//;
		push (@expected_failures, $_); }
	close(KNOWN);
}

if (defined($opt_skip)) {
	open(SKIP, "<$opt_skip") or die("unable to read skip file: $!");
	while (<SKIP>) { 
		chomp; 
		s/([ \t]+)\#(.*)$//;
		push (@skips, $_); }
	close(SKIP);
}

my $interfaces = join(',', ("127.0.0.6/8", 
			    "127.0.0.7/8",
			    "127.0.0.8/8",
			    "127.0.0.9/8",
			    "127.0.0.10/8",
			    "127.0.0.11/8"));

my $conffile = "$prefix_abs/client/client.conf";

sub write_clientconf($$)
{
	my ($conffile, $vars) = @_;

	mkdir("$prefix/client", 0777) unless -d "$prefix/client";
	
	if ( -d "$prefix/client/private" ) {
	        unlink <$prefix/client/private/*>;
	} else {
	        mkdir("$prefix/client/private", 0777);
	}

	open(CF, ">$conffile");
	print CF "[global]\n";
	if (defined($ENV{VALGRIND})) {
		print CF "\ticonv:native = true\n";
	} else {
		print CF "\ticonv:native = false\n";
	}
	print CF "\tnetbios name = client\n";
	if (defined($vars->{DOMAIN})) {
		print CF "\tworkgroup = $vars->{DOMAIN}\n";
	}
	if (defined($vars->{REALM})) {
		print CF "\trealm = $vars->{REALM}\n";
	}
	if (defined($vars->{NCALRPCDIR})) {
		print CF "\tncalrpc dir = $vars->{NCALRPCDIR}\n";
	}
	if (defined($vars->{PIDDIR})) {
		print CF "\tpid directory = $vars->{PIDDIR}\n";
	}
	if (defined($vars->{WINBINDD_SOCKET_DIR})) {
		print CF "\twinbindd socket directory = $vars->{WINBINDD_SOCKET_DIR}\n";
	}
	print CF "
	private dir = $prefix_abs/client/private
	js include = $srcdir_abs/scripting/libjs
	name resolve order = bcast
	interfaces = $interfaces
	panic action = $srcdir_abs/script/gdb_backtrace \%PID\% \%PROG\%
	max xmit = 32K
	notify:inotify = false
	ldb:nosync = true
	system:anonymous = true
	torture:basedir = $prefix_abs/client
#We don't want to pass our self-tests if the PAC code is wrong
	gensec:require_pac = true
";
	close(CF);
}


my @torture_options = ();
push (@torture_options, "--configfile=$conffile");
# ensure any one smbtorture call doesn't run too long
push (@torture_options, "--maximum-runtime=$torture_maxtime");
push (@torture_options, "--target=$opt_target");
push (@torture_options, "--basedir=$prefix");
push (@torture_options, "--option=torture:progress=no") if ($opt_format eq "buildfarm");
push (@torture_options, "--format=subunit");
push (@torture_options, "--option=torture:quick=yes") if ($opt_quick);

$ENV{TORTURE_OPTIONS} = join(' ', @torture_options);
print "OPTIONS $ENV{TORTURE_OPTIONS}\n";

my @todo = ();

my $testsdir = "$srcdir/selftest";
$ENV{SMB_CONF_PATH} = "$conffile";
$ENV{CONFIGURATION} = "--configfile=$conffile";

my %required_envs = ();

if ($opt_quick) {
	open(IN, "$testsdir/tests_quick.sh|");
} else {
	open(IN, "$testsdir/tests_all.sh|");
}
while (<IN>) {
	if ($_ eq "-- TEST --\n") {
		my $name = <IN>;
		$name =~ s/\n//g;
		my $env = <IN>;
		$env =~ s/\n//g;
		my $cmdline = <IN>;
		$cmdline =~ s/\n//g;
		if (not defined($tests) or $name =~ /$tests/) {
			$required_envs{$env} = 1;
			push (@todo, [$name, $env, $cmdline]);
		}
	} else {
		print;
	}
}
close(IN) or die("Error creating recipe");

my $suitestotal = $#todo + 1;
my $i = 0;
$| = 1;

my %running_envs = ();

my @exported_envvars = (
	# domain stuff
	"DOMAIN",
	"REALM",

	# domain controller stuff
	"DC_SERVER",
	"DC_SERVER_IP",
	"DC_NETBIOSNAME",
	"DC_NETBIOSALIAS",

	# server stuff
	"SERVER",
	"SERVER_IP",
	"NETBIOSNAME",
	"NETBIOSALIAS",

	# user stuff
	"USERNAME",
	"PASSWORD",
	"DC_USERNAME",
	"DC_PASSWORD",

	# misc stuff
	"KRB5_CONFIG",
	"WINBINDD_SOCKET_DIR"
);

sub setup_env($)
{
	my ($envname) = @_;

	my $testenv_vars;
	if ($envname eq "none") {
		$testenv_vars = {};
	} elsif (defined($running_envs{$envname})) {
		$testenv_vars = $running_envs{$envname};
		if (not $target->check_env($testenv_vars)) {
			$testenv_vars = undef;
		}
	} else {
		$testenv_vars = $target->setup_env($envname, $prefix);
	}

	return undef unless defined($testenv_vars);

	SocketWrapper::set_default_iface(6);
	write_clientconf($conffile, $testenv_vars);

	foreach (@exported_envvars) {
		if (defined($testenv_vars->{$_})) {
			$ENV{$_} = $testenv_vars->{$_};
		} else {
			delete $ENV{$_};
		}
	}

	$running_envs{$envname} = $testenv_vars;
	return $testenv_vars;
}

sub exported_envvars_str($)
{
	my ($testenv_vars) = @_;
	my $out = "";

	foreach (@exported_envvars) {
		next unless defined($testenv_vars->{$_});
		$out .= $_."=".$testenv_vars->{$_}."\n";
	}

	return $out;
}

sub getlog_env($)
{
	my ($envname) = @_;
	return "" if ($envname eq "none");
	return $target->getlog_env($running_envs{$envname});
}

sub check_env($)
{
	my ($envname) = @_;
	return 1 if ($envname eq "none");
	return $target->check_env($running_envs{$envname});
}

sub teardown_env($)
{
	my ($envname) = @_;
	return if ($envname eq "none");
	$target->teardown_env($running_envs{$envname});
	delete $running_envs{$envname};
}

my $msg_ops;
if ($opt_format eq "buildfarm") {
	require output::buildfarm;
	$msg_ops = new output::buildfarm();
} elsif ($opt_format eq "plain") {
	require output::plain;
	$msg_ops = new output::plain($opt_verbose, $opt_immediate, $statistics);
} elsif ($opt_format eq "html") {
	require output::html;
	mkdir("test-results", 0777);
	$msg_ops = new output::html("test-results", $statistics);
} else {
	die("Invalid output format '$opt_format'");
}

if ($opt_no_lazy_setup) {
	setup_env($_) foreach (keys %required_envs);
}

if ($opt_testenv) {
	my $testenv_name = $ENV{SELFTEST_TESTENV};
	$testenv_name = "dc" unless defined($testenv_name);

	my $testenv_vars = setup_env($testenv_name);

	$ENV{PIDDIR} = $testenv_vars->{PIDDIR};

	my $envvarstr = exported_envvars_str($testenv_vars);

	my $term = ($ENV{TERM} or "xterm");
	system("$term -e 'echo -e \"
Welcome to the Samba4 Test environment '$testenv_name'

This matches the client environment used in make test
smbd is pid `cat \$PIDDIR/smbd.pid`

Some useful environment variables:
TORTURE_OPTIONS=\$TORTURE_OPTIONS
CONFIGURATION=\$CONFIGURATION

$envvarstr
\" && bash'");
	teardown_env($testenv_name);
} else {
	foreach (@todo) {
		$i++;
		my $cmd = $$_[2];
		$cmd =~ s/([\(\)])/\\$1/g;
		my $name = $$_[0];
		my $envname = $$_[1];
		
		if (skip($name)) {
			$msg_ops->skip_testsuite($name);
			$statistics->{SUITES_SKIPPED}++;
			next;
		}

		my $envvars = setup_env($envname);
		if (not defined($envvars)) {
			$statistics->{SUITES_FAIL}++;
			$statistics->{TESTS_ERROR}++;
			$msg_ops->missing_env($name, $envname);
			next;
		}

		run_testsuite($envname, $name, $cmd, $i, $suitestotal, $msg_ops);

		if (defined($opt_analyse_cmd)) {
			system("$opt_analyse_cmd \"$name\"");
		}

		teardown_env($envname) if ($opt_resetup_env);
	}
}

print "\n";

teardown_env($_) foreach (keys %running_envs);

$target->stop();

$statistics->{END_TIME} = time();
my $duration = ($statistics->{END_TIME}-$statistics->{START_TIME});
$msg_ops->summary();
print "DURATION: $duration seconds\n";

my $failed = 0;

# if there were any valgrind failures, show them
foreach (<$prefix/valgrind.log*>) {
	next unless (-s $_);
	system("grep DWARF2.CFI.reader $_ > /dev/null");
	if ($? >> 8 == 0) {
	    print "VALGRIND FAILURE\n";
	    $failed++;
	    system("cat $_");
	}
}

if ($opt_format eq "buildfarm") {
	print "TEST STATUS: $statistics->{SUITES_FAIL}\n";
}

exit $statistics->{SUITES_FAIL};
