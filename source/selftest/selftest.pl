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
use Samba3;
use Samba4;
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

my $srcdir = ".";
my $builddir = ".";
my $prefix = "./st";

my $suitesfailed = [];
my $start = time();
my @expected_failures = ();
my @skips = ();

my $statistics = {
	SUITES_FAIL => 0,
	SUITES_OK => 0,
	SUITES_SKIPPED => 0,

	TESTS_UNEXPECTED_OK => 0,
	TESTS_EXPECTED_OK => 0,
	TESTS_UNEXPECTED_FAIL => 0,
	TESTS_EXPECTED_FAIL => 0,
	TESTS_ERROR => 0
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

my $test_output = {};

sub buildfarm_start_msg($)
{
	my ($state) = @_;
	my $out = "";

	$out .= "--==--==--==--==--==--==--==--==--==--==--\n";
	$out .= "Running test $state->{NAME} (level 0 stdout)\n";
	$out .= "--==--==--==--==--==--==--==--==--==--==--\n";
	$out .= scalar(localtime())."\n";
	$out .= "SELFTEST RUNTIME: " . ($state->{START} - $start) . "s\n";
	$out .= "NAME: $state->{NAME}\n";
	$out .= "CMD: $state->{CMD}\n";

	$test_output->{$state->{NAME}} = "";

	print $out;
}

sub buildfarm_output_msg($$)
{
	my ($state, $output) = @_;

	$test_output->{$state->{NAME}} .= $output;
}

sub buildfarm_end_msg($$$)
{
	my ($state, $expected_ret, $ret) = @_;
	my $out = "";

	$out .= "TEST RUNTIME: " . (time() - $state->{START}) . "s\n";

	if ($ret == $expected_ret) {
		$out .= "ALL OK\n";
	} else {
		$out .= "ERROR: $ret";
		$out .= $test_output->{$state->{NAME}};
	}

	$out .= "PCAP FILE: $state->{PCAP_FILE}\n" if defined($state->{PCAP_FILE});

	$out .= getlog_env($state->{ENVNAME});

	$out .= "==========================================\n";
	if ($ret == $expected_ret) {
		$out .= "TEST PASSED: $state->{NAME}\n";
	} else {
		$out .= "TEST FAILED: $state->{NAME} (status $ret)\n";
	}
	$out .= "==========================================\n";

	print $out;
}

my $buildfarm_msg_ops = {
	start_msg	=> \&buildfarm_start_msg,
	output_msg	=> \&buildfarm_output_msg,
	end_msg		=> \&buildfarm_end_msg
};

sub plain_output_msg($$);

sub plain_start_msg($)
{
	my ($state) = @_;
	my $out = "";

	$out .= "[$state->{INDEX}/$state->{TOTAL} in " . ($state->{START} - $start) . "s";
	$out .= ", ".($#$suitesfailed+1)." errors" if ($#$suitesfailed+1 > 0);
	$out .= "] $state->{NAME}\n";

	$test_output->{$state->{NAME}} = "" unless $opt_verbose;

	plain_output_msg($state, "CMD: $state->{CMD}\n");

	print $out;
}

sub plain_output_msg($$)
{
	my ($state, $output) = @_;

	if ($opt_verbose) {
		print $output;
	} else {
		$test_output->{$state->{NAME}} .= $output;
	}
}

sub plain_end_msg($$$)
{
	my ($state, $expected_ret, $ret) = @_;
	my $out = "";

	if ($ret != $expected_ret) {
		plain_output_msg($state, "ERROR: $ret\n");
	}

	if ($ret != $expected_ret and ($opt_immediate or $opt_one) and not $opt_verbose) {
		$out .= $test_output->{$state->{NAME}};
	}

	if (not $opt_socket_wrapper_keep_pcap and defined($state->{PCAP_FILE})) {
		$out .= "PCAP FILE: $state->{PCAP_FILE}\n";
	}

	$out .= getlog_env($state->{ENVNAME});

	print $out;
}

my $plain_msg_ops = {
	start_msg	=> \&plain_start_msg,
	output_msg	=> \&plain_output_msg,
	end_msg		=> \&plain_end_msg
};

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

sub run_test($$$$$$)
{
	my ($envname, $name, $cmd, $i, $totalsuites, $msg_ops) = @_;
	my $expected_ret = 1;
	my $open_tests = {};
	my $msg_state = {
		ENVNAME	=> $envname,
		NAME	=> $name,
		CMD	=> $cmd,
		INDEX	=> $i,
		TOTAL	=> $totalsuites,
		START	=> time()
	};

	setup_pcap($msg_state);

	$msg_ops->{start_msg}->($msg_state);

	open(RESULT, "$cmd 2>&1|");
	while (<RESULT>) {
		$msg_ops->{output_msg}->($msg_state, $_);
		if (/^test: (.+)\n/) {
			$open_tests->{$1} = 1;
		} elsif (/^(success|failure|skip|error): (.*?)( \[)?\n/) {
			my $result = $1;
			if ($1 eq "success") {
				delete $open_tests->{$2};
				if (expecting_failure("$name/$2")) {
					$statistics->{TESTS_UNEXPECTED_OK}++;
				} else {
					$statistics->{TESTS_EXPECTED_OK}++;
				}
			} elsif ($1 eq "failure") {
				delete $open_tests->{$2};
				if (expecting_failure("$name/$2")) {
					$statistics->{TESTS_EXPECTED_FAIL}++;
					$expected_ret = 0;
				} else {
					print "n:$name/$2l\n";
					$statistics->{TESTS_UNEXPECTED_FAIL}++;
				}
			} elsif ($1 eq "skip") {
				delete $open_tests->{$2};
			} elsif ($1 eq "error") {
				$statistics->{TESTS_ERROR}++;
				delete $open_tests->{$2};
			}
		}
	}
	foreach (keys %$open_tests) {
		$msg_ops->{output_msg}->($msg_state, "$_ was started but never finished!\n");
		$statistics->{TESTS_ERROR}++;
	}
	my $ret = close(RESULT);

	cleanup_pcap($msg_state,  $expected_ret, $ret);

	$msg_ops->{end_msg}->($msg_state, $expected_ret, $ret);

	if ($ret != $expected_ret) {
		push(@$suitesfailed, $name);
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
 --ldap=openldap|fedora     back smbd onto specified ldap server

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
		$ldap = "fedora";
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
$ENV{SRCDIR} = $srcdir;

my $tls_enabled = not $opt_quick;
my $from_build_farm = (defined($ENV{RUN_FROM_BUILD_FARM}) and 
                      ($ENV{RUN_FROM_BUILD_FARM} eq "yes"));

$ENV{TLS_ENABLED} = ($tls_enabled?"yes":"no");
$ENV{LD_LDB_MODULE_PATH} = "$old_pwd/bin/modules/ldb";
$ENV{LD_SAMBA_MODULE_PATH} = "$old_pwd/bin/modules";
if (defined($ENV{LD_LIBRARY_PATH})) {
	$ENV{LD_LIBRARY_PATH} = "$old_pwd/bin/shared:$ENV{LD_LIBRARY_PATH}";
} else {
	$ENV{LD_LIBRARY_PATH} = "$old_pwd/bin/shared";
}
$ENV{PKG_CONFIG_PATH} = "$old_pwd/bin/pkgconfig:$ENV{PKG_CONFIG_PATH}";
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
push (@torture_options, "--option=torture:progress=no") if ($from_build_farm);
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
	"KRB5_CONFIG"
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
if ($from_build_farm) {
	$msg_ops = $buildfarm_msg_ops;
} else {
	$msg_ops = $plain_msg_ops;
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
			print "SKIPPED: $name\n";
			$statistics->{SUITES_SKIPPED}++;
			next;
		}

		my $envvars = setup_env($envname);
		if (not defined($envvars)) {
			push(@$suitesfailed, $name);
			$statistics->{SUITES_FAIL}++;
			$statistics->{TESTS_ERROR}++;
			print "FAIL: $name (ENV[$envname] not available!)\n";
			next;
		}

		run_test($envname, $name, $cmd, $i, $suitestotal, $msg_ops);

		if (defined($opt_analyse_cmd)) {
			system("$opt_analyse_cmd \"$name\"");
		}

		teardown_env($envname) if ($opt_resetup_env);
	}
}

print "\n";

teardown_env($_) foreach (keys %running_envs);

$target->stop();

my $end = time();
my $duration = ($end-$start);
my $numfailed = $#$suitesfailed+1;
if ($numfailed == 0) {
	my $ok = $statistics->{TESTS_EXPECTED_OK} + 
	         $statistics->{TESTS_EXPECTED_FAIL};
	print "ALL OK ($ok tests in $statistics->{SUITES_OK} testsuites)\n";
} else {
	unless ($from_build_farm) {
		if (not $opt_immediate and not $opt_verbose) {
			foreach (@$suitesfailed) {
				print "===============================================================================\n";
				print "FAIL: $_\n";
				print $test_output->{$_};
				print "\n";
			}
		}

		print "FAILED ($statistics->{TESTS_UNEXPECTED_FAIL} failures and $statistics->{TESTS_ERROR} errors in $statistics->{SUITES_FAIL} testsuites)\n";
	}
}
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

if ($from_build_farm) {
	print "TEST STATUS: $numfailed\n";
}

exit $numfailed;
