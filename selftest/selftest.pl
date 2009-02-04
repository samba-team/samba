#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2008 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2007-2009 Stefan Metzmacher <metze@samba.org>
# Published under the GNU GPL, v3 or later.

=pod

=head1 NAME

selftest - Samba test runner

=head1 SYNOPSIS

selftest --help

selftest [--srcdir=DIR] [--builddir=DIR] [--exeext=EXT][--target=samba4|samba3|win|kvm] [--socket-wrapper] [--quick] [--exclude=FILE] [--include=FILE] [--one] [--prefix=prefix] [--immediate] [--testlist=FILE] [TESTS]

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

=item I<--exeext=EXT>

Executable extention

=item I<--prefix=DIR>

Change directory to run tests in. Default is 'st'.

=item I<--immediate>

Show errors as soon as they happen rather than at the end of the test run.
		
=item I<--target samba4|samba3|win|kvm>

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

TESTSUITE-NAME.TEST-NAME

The reason for a test can also be specified, by adding a hash sign (#) and the reason 
after the test name.

=item I<--exclude>

Specify a file containing a list of tests that should be skipped. Possible 
candidates are tests that segfault the server, flip or don't end. The format of this file is the same as 
for the --expected-failures flag.

=item I<--include>

Specify a file containing a list of tests that should be run. Same format 
as the --exclude flag.

Not includes specified means all tests will be run.

=item I<--one>

Abort as soon as one test fails.

=item I<--testlist>

Load a list of tests from the specified location.

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
my @opt_exclude = ();
my @opt_include = ();
my $opt_verbose = 0;
my $opt_image = undef;
my $opt_testenv = 0;
my $ldap = undef;
my $opt_analyse_cmd = undef;
my $opt_resetup_env = undef;
my $opt_bindir = undef;
my $opt_no_lazy_setup = undef;
my $opt_format = "plain";
my @testlists = ();

my $srcdir = ".";
my $builddir = ".";
my $exeext = "";
my $prefix = "./st";

my @expected_failures = ();
my @includes = ();
my @excludes = ();

my $statistics = {
	SUITES_FAIL => 0,

	TESTS_UNEXPECTED_OK => 0,
	TESTS_EXPECTED_OK => 0,
	TESTS_UNEXPECTED_FAIL => 0,
	TESTS_EXPECTED_FAIL => 0,
	TESTS_ERROR => 0,
	TESTS_SKIP => 0,
};

sub find_in_list($$)
{
	my ($list, $fullname) = @_;

	foreach (@$list) {
		if ($fullname =~ /$$_[0]/) {
			 return ($$_[1]) if ($$_[1]);
			 return "NO REASON SPECIFIED";
		}
	}

	return undef;
}

sub expecting_failure($)
{
	my ($name) = @_;
	return find_in_list(\@expected_failures, $name);
}

sub skip($)
{
	my ($name) = @_;

	return find_in_list(\@excludes, $name);
}

sub getlog_env($);

sub setup_pcap($)
{
	my ($name) = @_;

	return unless ($opt_socket_wrapper_pcap);
	return unless defined($ENV{SOCKET_WRAPPER_PCAP_DIR});

	my $fname = $name;
	$fname =~ s%[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\-]%_%g;

	my $pcap_file = "$ENV{SOCKET_WRAPPER_PCAP_DIR}/$fname.pcap";

	SocketWrapper::setup_pcap($pcap_file);

	return $pcap_file;
}

sub cleanup_pcap($$$)
{
	my ($pcap_file, $expected_ret, $ret) = @_;

	return unless ($opt_socket_wrapper_pcap);
	return if ($opt_socket_wrapper_keep_pcap);
	return unless ($expected_ret == $ret);
	return unless defined($pcap_file);

	unlink($pcap_file);
}

sub run_testsuite($$$$$$)
{
	my ($envname, $name, $cmd, $i, $totalsuites, $msg_ops) = @_;
	my $pcap_file = setup_pcap($name);

	$msg_ops->start_test([], $name);

	unless (open(RESULT, "$cmd 2>&1|")) {
		$statistics->{TESTS_ERROR}++;
		$msg_ops->end_test([], $name, "error", 1, "Unable to run $cmd: $!");
		$statistics->{SUITES_FAIL}++;
		return 0;
	}

	my $expected_ret = parse_results(
		$msg_ops, $statistics, *RESULT, \&expecting_failure, [$name]);

	my $envlog = getlog_env($envname);
	$msg_ops->output_msg("ENVLOG: $envlog\n") if ($envlog ne "");

	$msg_ops->output_msg("CMD: $cmd\n");

	my $ret = close(RESULT);
	$ret = 0 unless $ret == 1;

	my $exitcode = $? >> 8;

	if ($ret == 1) {
		$msg_ops->end_test([], $name, "success", $expected_ret != $ret, undef); 
	} else {
		$msg_ops->end_test([], $name, "failure", $expected_ret != $ret, "Exit code was $exitcode");
	}

	cleanup_pcap($pcap_file, $expected_ret, $ret);

	if (not $opt_socket_wrapper_keep_pcap and defined($pcap_file)) {
		$msg_ops->output_msg("PCAP FILE: $pcap_file\n");
	}

	if ($ret != $expected_ret) {
		$statistics->{SUITES_FAIL}++;
		exit(1) if ($opt_one);
	}

	return ($ret == $expected_ret);
}

sub ShowHelp()
{
	print "Samba test runner
Copyright (C) Jelmer Vernooij <jelmer\@samba.org>
Copyright (C) Stefan Metzmacher <metze\@samba.org>

Usage: $Script [OPTIONS] TESTNAME-REGEX

Generic options:
 --help                     this help page
 --target=samba[34]|win|kvm Samba version to target
 --testlist=FILE	    file to read available tests from

Paths:
 --prefix=DIR               prefix to run tests in [st]
 --srcdir=DIR               source directory [.]
 --builddir=DIR             output directory [.]
 --exeext=EXT               executable extention []

Target Specific:
 --socket-wrapper-pcap	    save traffic to pcap directories
 --socket-wrapper-keep-pcap keep all pcap files, not just those for tests that 
                            failed
 --socket-wrapper           enable socket wrapper
 --bindir=PATH              path to target binaries
 --expected-failures=FILE   specify list of tests that is guaranteed to fail

Samba4 Specific:
 --ldap=openldap|fedora-ds  back samba onto specified ldap server

Kvm Specific:
 --image=PATH               path to KVM image

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
		'exclude=s' => \@opt_exclude,
		'include=s' => \@opt_include,
		'srcdir=s' => \$srcdir,
		'builddir=s' => \$builddir,
		'exeext=s' => \$exeext,
		'verbose' => \$opt_verbose,
		'testenv' => \$opt_testenv,
		'ldap:s' => \$ldap,
		'analyse-cmd=s' => \$opt_analyse_cmd,
		'no-lazy-setup' => \$opt_no_lazy_setup,
		'resetup-environment' => \$opt_resetup_env,
		'bindir:s' => \$opt_bindir,
		'format=s' => \$opt_format,
		'image=s' => \$opt_image,
		'testlist=s' => \@testlists
	    );

exit(1) if (not $result);

ShowHelp() if ($opt_help);

my $tests = shift;

# quick hack to disable rpc validation when using valgrind - its way too slow
unless (defined($ENV{VALGRIND})) {
	$ENV{VALIDATE} = "validate";
	$ENV{MALLOC_CHECK_} = 2;
}

my $bindir = ($opt_bindir or "$builddir/bin");
my $bindir_abs = abs_path($bindir);

# Backwards compatibility:
if (defined($ENV{TEST_LDAP}) and $ENV{TEST_LDAP} eq "yes") {
	if (defined($ENV{FEDORA_DS_ROOT})) {
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
my $builddir_abs = abs_path($builddir);

die("using an empty absolute prefix isn't allowed") unless $prefix_abs ne "";
die("using '/' as absolute prefix isn't allowed") unless $prefix_abs ne "/";

$ENV{PREFIX} = $prefix;
$ENV{KRB5CCNAME} = "$prefix/krb5ticket";
$ENV{PREFIX_ABS} = $prefix_abs;
$ENV{SRCDIR} = $srcdir;
$ENV{SRCDIR_ABS} = $srcdir_abs;
$ENV{BUILDDIR} = $builddir;
$ENV{BUILDDIR_ABS} = $builddir_abs;
$ENV{EXEEXT} = $exeext;

if (defined($ENV{RUN_FROM_BUILD_FARM}) and 
	($ENV{RUN_FROM_BUILD_FARM} eq "yes")) {
	$opt_format = "buildfarm";
}

my $tls_enabled = not $opt_quick;
$ENV{TLS_ENABLED} = ($tls_enabled?"yes":"no");
$ENV{LDB_MODULES_PATH} = "$bindir_abs/modules/ldb";
$ENV{LD_SAMBA_MODULE_PATH} = "$bindir_abs/modules";
sub prefix_pathvar($$)
{
	my ($name, $newpath) = @_;
	if (defined($ENV{$name})) {
		$ENV{$name} = "$newpath:$ENV{$name}";
	} else {
		$ENV{$name} = $newpath;
	}
}
prefix_pathvar("PKG_CONFIG_PATH", "$bindir_abs/pkgconfig");
prefix_pathvar("PYTHONPATH", "$bindir_abs/python");

if ($opt_socket_wrapper_keep_pcap) {
	# Socket wrapper keep pcap implies socket wrapper pcap
	$opt_socket_wrapper_pcap = 1;
}

if ($opt_socket_wrapper_pcap) {
	# Socket wrapper pcap implies socket wrapper
	$opt_socket_wrapper = 1;
}

my $socket_wrapper_dir;
if ($opt_socket_wrapper) {
	$socket_wrapper_dir = SocketWrapper::setup_dir("$prefix/w", $opt_socket_wrapper_pcap);
	print "SOCKET_WRAPPER_DIR=$socket_wrapper_dir\n";
} else {
	 unless ($< == 0) { 
		 print "WARNING: Not using socket wrapper, but also not running as root. Will not be able to listen on proper ports\n";
	 }
}

my $target;
my $testenv_default = "none";

if ($opt_target eq "samba4") {
	$testenv_default = "member";
	require target::Samba4;
	$target = new Samba4($bindir, $ldap, "$srcdir/setup", $exeext);
} elsif ($opt_target eq "samba3") {
	if ($opt_socket_wrapper and `$bindir/smbd -b | grep SOCKET_WRAPPER` eq "") {
		die("You must include --enable-socket-wrapper when compiling Samba in order to execute 'make test'.  Exiting....");
	}
	$testenv_default = "member";
	require target::Samba3;
	$target = new Samba3($bindir);
} elsif ($opt_target eq "win") {
	die("Windows tests will not run with socket wrapper enabled.") 
		if ($opt_socket_wrapper);
	$testenv_default = "dc";
	require target::Windows;
	$target = new Windows();
} elsif ($opt_target eq "kvm") {
	die("Kvm tests will not run with socket wrapper enabled.") 
		if ($opt_socket_wrapper);
	require target::Kvm;
	die("No image specified") unless ($opt_image);
	$target = new Kvm($opt_image, undef);
}

#
# Start a Virtual Distributed Ethernet Switch
# Returns the pid of the switch.
#
sub start_vde_switch($)
{
	my ($path) = @_;

	system("vde_switch --pidfile $path/vde.pid --sock $path/vde.sock --daemon");

	open(PID, "$path/vde.pid");
	<PID> =~ /([0-9]+)/;
	my $pid = $1;
	close(PID);

	return $pid;
}

# Stop a Virtual Distributed Ethernet Switch
sub stop_vde_switch($)
{
	my ($pid) = @_;
	kill 9, $pid;
}

sub read_test_regexes($)
{
	my ($name) = @_;
	my @ret = ();
	open(LF, "<$name") or die("unable to read $name: $!");
	while (<LF>) { 
		chomp; 
		next if (/^#/);
		if (/^(.*?)([ \t]+)\#([\t ]*)(.*?)$/) {
			push (@ret, [$1, $4]);
		} else {
			s/^(.*?)([ \t]+)\#([\t ]*)(.*?)$//;
			push (@ret, [$_, undef]); 
		}
	}
	close(LF);
	return @ret;
}

if (defined($opt_expected_failures)) {
	@expected_failures = read_test_regexes($opt_expected_failures);
}

foreach (@opt_exclude) {
	push (@excludes, read_test_regexes($_));
}

foreach (@opt_include) {
	push (@includes, read_test_regexes($_));
}

my $interfaces = join(',', ("127.0.0.6/8", 
			    "127.0.0.7/8",
			    "127.0.0.8/8",
			    "127.0.0.9/8",
			    "127.0.0.10/8",
			    "127.0.0.11/8"));

my $conffile = "$prefix_abs/client/client.conf";
$ENV{SMB_CONF_PATH} = $conffile;

sub write_clientconf($$)
{
	my ($conffile, $vars) = @_;

	mkdir("$prefix/client", 0777) unless -d "$prefix/client";
	
	if ( -d "$prefix/client/private" ) {
	        unlink <$prefix/client/private/*>;
	} else {
	        mkdir("$prefix/client/private", 0777);
	}

	if ( -d "$prefix/client/lock" ) {
	        unlink <$prefix/client/lockdir/*>;
	} else {
	        mkdir("$prefix/client/lockdir", 0777);
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
	if ($opt_socket_wrapper) {
		print CF "\tinterfaces = $interfaces\n";
	}
	print CF "
	private dir = $prefix_abs/client/private
	lock dir = $prefix_abs/client/lockdir
	name resolve order = bcast
	panic action = $RealBin/gdb_backtrace \%PID\% \%PROG\%
	max xmit = 32K
	notify:inotify = false
	ldb:nosync = true
	system:anonymous = true
	client lanman auth = Yes
	torture:basedir = $prefix_abs/client
#We don't want to pass our self-tests if the PAC code is wrong
	gensec:require_pac = true
	modules dir = $ENV{LD_SAMBA_MODULE_PATH}
";
	close(CF);
}

my @todo = ();

my $testsdir = "$srcdir/selftest";

my %required_envs = ();

sub read_testlist($)
{
	my ($filename) = @_;

	my @ret = ();
	open(IN, $filename) or die("Unable to open $filename: $!");

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
				push (@ret, [$name, $env, $cmdline]);
			}
		} else {
			print;
		}
	}
	close(IN) or die("Error creating recipe");
	return @ret;
}

if ($#testlists == -1) {
	die("No testlists specified");
}

$ENV{SELFTEST_PREFIX} = "$prefix_abs";
if ($opt_socket_wrapper) {
	$ENV{SELFTEST_INTERFACES} = $interfaces;
} else {
	$ENV{SELFTEST_INTERFACES} = "";
}
if ($opt_verbose) {
	$ENV{SELFTEST_VERBOSE} = "1";
} else {
	$ENV{SELFTEST_VERBOSE} = "";
}
if ($opt_quick) {
	$ENV{SELFTEST_QUICK} = "1";
} else {
	$ENV{SELFTEST_QUICK} = "";
}
$ENV{SELFTEST_TARGET} = $opt_target;
$ENV{SELFTEST_MAXTIME} = $torture_maxtime;

my @available = ();
foreach my $fn (@testlists) {
	foreach (read_testlist($fn)) {
		my $name = $$_[0];
		next if (@includes and not find_in_list(\@includes, $name));
		push (@available, $_);
	}
}

my $msg_ops;
if ($opt_format eq "buildfarm") {
	require output::buildfarm;
	$msg_ops = new output::buildfarm($statistics);
} elsif ($opt_format eq "plain") {
	require output::plain;
	$msg_ops = new output::plain("$prefix/summary", $opt_verbose, $opt_immediate, $statistics, $#available+1);
} elsif ($opt_format eq "html") {
	require output::html;
	mkdir("test-results", 0777);
	$msg_ops = new output::html("test-results", $statistics);
} else {
	die("Invalid output format '$opt_format'");
}


foreach (@available) {
	my $name = $$_[0];
	my $skipreason = skip($name);
	if ($skipreason) {
		$msg_ops->skip_testsuite($name, $skipreason);
	} else {
		push(@todo, $_); 
	}
}

if ($#todo == -1) {
	print STDERR "No tests to run\n";
	exit(1);
	}

my $suitestotal = $#todo + 1;
my $i = 0;
$| = 1;

my %running_envs = ();

sub get_running_env($)
{
	my ($name) = @_;

	my $envname = $name;

	$envname =~ s/:.*//;

	return $running_envs{$envname};
}

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
	"WINBINDD_SOCKET_DIR",
	"WINBINDD_PRIV_PIPE_DIR"
);

$SIG{INT} = $SIG{QUIT} = $SIG{TERM} = sub { 
	my $signame = shift;
	teardown_env($_) foreach(keys %running_envs);
	die("Received signal $signame");
};

sub setup_env($)
{
	my ($name) = @_;

	my $testenv_vars = undef;

	my $envname = $name;
	my $option = $name;

	$envname =~ s/:.*//;
	$option =~ s/^[^:]*//;
	$option =~ s/^://;

	$option = "client" if $option eq "";

	if ($envname eq "none") {
		$testenv_vars = {};
	} elsif (defined(get_running_env($envname))) {
		$testenv_vars = get_running_env($envname);
		if (not $target->check_env($testenv_vars)) {
			$testenv_vars = undef;
		}
	} else {
		$testenv_vars = $target->setup_env($envname, $prefix);
	}

	return undef unless defined($testenv_vars);

	$running_envs{$envname} = $testenv_vars;

	if ($option eq "local") {
		SocketWrapper::set_default_iface($testenv_vars->{SOCKET_WRAPPER_DEFAULT_IFACE});
		$ENV{SMB_CONF_PATH} = $testenv_vars->{SERVERCONFFILE};
	} elsif ($option eq "client") {
		SocketWrapper::set_default_iface(6);
		write_clientconf($conffile, $testenv_vars);
		$ENV{SMB_CONF_PATH} = $conffile;
	} else {
		die("Unknown option[$option] for envname[$envname]");
	}

	foreach (@exported_envvars) {
		if (defined($testenv_vars->{$_})) {
			$ENV{$_} = $testenv_vars->{$_};
		} else {
			delete $ENV{$_};
		}
	}

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
	return $target->getlog_env(get_running_env($envname));
}

sub check_env($)
{
	my ($envname) = @_;
	return 1 if ($envname eq "none");
	return $target->check_env(get_running_env($envname));
}

sub teardown_env($)
{
	my ($envname) = @_;
	return if ($envname eq "none");
	$target->teardown_env(get_running_env($envname));
	delete $running_envs{$envname};
}

if ($opt_no_lazy_setup) {
	setup_env($_) foreach (keys %required_envs);
}

if ($opt_testenv) {
	my $testenv_name = $ENV{SELFTEST_TESTENV};
	$testenv_name = $testenv_default unless defined($testenv_name);

	my $testenv_vars = setup_env($testenv_name);

	$ENV{PIDDIR} = $testenv_vars->{PIDDIR};

	my $envvarstr = exported_envvars_str($testenv_vars);

	my $term = ($ENV{TERM} or "xterm");
	system("$term -e 'echo -e \"
Welcome to the Samba4 Test environment '$testenv_name'

This matches the client environment used in make test
server is pid `cat \$PIDDIR/samba.pid`

Some useful environment variables:
TORTURE_OPTIONS=\$TORTURE_OPTIONS
SMB_CONF_PATH=\$SMB_CONF_PATH

$envvarstr
\" && LD_LIBRARY_PATH=$ENV{LD_LIBRARY_PATH} bash'");
	teardown_env($testenv_name);
} else {
	foreach (@todo) {
		$i++;
		my $cmd = $$_[2];
		$cmd =~ s/([\(\)])/\\$1/g;
		my $name = $$_[0];
		my $envname = $$_[1];
		
		my $envvars = setup_env($envname);
		if (not defined($envvars)) {
			$msg_ops->skip_testsuite($name, "unable to set up environment $envname");
			next;
		}

		run_testsuite($envname, $name, $cmd, $i, $suitestotal, 
		              $msg_ops);

		if (defined($opt_analyse_cmd)) {
			system("$opt_analyse_cmd \"$name\"");
		}

		teardown_env($envname) if ($opt_resetup_env);
	}
}

print "\n";

teardown_env($_) foreach (keys %running_envs);

$target->stop();

$msg_ops->summary();

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
