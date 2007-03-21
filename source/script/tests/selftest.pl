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
use warnings;

use FindBin qw($RealBin $Script);
use File::Spec;
use Getopt::Long;
use POSIX;
use Cwd;
use lib "$RealBin";
use Samba3;
use Samba4;
use SocketWrapper;

my $opt_help = 0;
my $opt_target = "samba4";
my $opt_quick = 0;
my $opt_socket_wrapper = 0;
my $opt_socket_wrapper_pcap = undef;
my $opt_one = 0;
my $opt_immediate = 0;
my $opt_expected_failures = undef;
my $opt_skip = undef;
my $opt_verbose = 0;
my $opt_testenv = 0;
my $opt_ldap = undef;
my $opt_analyse_cmd = undef;

my $srcdir = ".";
my $builddir = ".";
my $prefix = "st";

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

	return 1 if (grep(/^$fullname$/, @expected_failures));

	return 0;
}

sub skip($)
{
	my $fullname = shift;

	return 1 if (grep(/^$fullname$/, @skips));
	return 0;
}

sub run_test_buildfarm($$$$)
{
	my ($name, $cmd, $i, $suitestotal) = @_;
	print "--==--==--==--==--==--==--==--==--==--==--\n";
	print "Running test $name (level 0 stdout)\n";
	print "--==--==--==--==--==--==--==--==--==--==--\n";
	system("date");

	my $expected_ret = 1;
	my $open_tests = {};
	open(RESULT, "$cmd 2>&1|");
	while (<RESULT>) { 
		print;
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
	print "COMMAND: $cmd\n";
	foreach (keys %$open_tests) {
		print "$_ was started but never finished!\n";		
		$statistics->{TESTS_ERROR}++;
	}
	my $ret = close(RESULT);

	print "==========================================\n";
	if ($ret == $expected_ret) {
		print "TEST PASSED: $name\n";
	} else {
		print "TEST FAILED: $name (status $ret)\n";
	}
	print "==========================================\n";
}

my $test_output = {};
sub run_test_plain($$$$)
{
	my ($name, $cmd, $i, $totalsuites) = @_;
	my $err = "";
	if ($#$suitesfailed+1 > 0) { $err = ", ".($#$suitesfailed+1)." errors"; }
	printf "[$i/$totalsuites in " . (time() - $start)."s$err] $name\n";
	open(RESULT, "$cmd 2>&1|");
	my $expected_ret = 1;
	my $open_tests = {};
	$test_output->{$name} = "";
	while (<RESULT>) { 
		$test_output->{$name}.=$_;
		print if ($opt_verbose);
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
	$test_output->{$name}.="COMMAND: $cmd\n";
	foreach (keys %$open_tests) {
		$test_output->{$name}.="$_ was started but never finished!\n";		
		$statistics->{TESTS_ERROR}++;
	}
	my $ret = close(RESULT);
	if ($ret != $expected_ret and ($opt_immediate or $opt_one) and not $opt_verbose) {
		print "$test_output->{$name}\n";
	}
	if ($ret != $expected_ret) {
		push(@$suitesfailed, $name);
		$statistics->{SUITES_FAIL}++;
		exit(1) if ($opt_one);
	} else {
		$statistics->{SUITES_OK}++;
	}
}

sub ShowHelp()
{
	print "Samba test runner
Copyright (C) Jelmer Vernooij <jelmer\@samba.org>

Usage: $Script [OPTIONS] PREFIX

Generic options:
 --help                     this help page

Paths:
 --prefix=DIR               prefix to run tests in [st]
 --srcdir=DIR               source directory [.]
 --builddir=DIR             output directory [.]

Target Specific:
 --target=samba4|samba3|win Samba version to target
 --socket-wrapper-pcap=FILE save traffic to pcap file
 --socket-wrapper           enable socket wrapper
 --expected-failures=FILE   specify list of tests that is guaranteed to fail
 --ldap                     run against ldap

Behaviour:
 --quick                    run quick overall test
 --one                      abort when the first test fails
 --immediate                print test output for failed tests during run
 --verbose                  be verbose
 --analyse-cmd CMD			command to run after each test
";
	exit(0);
}

my $result = GetOptions (
	    'help|h|?' => \$opt_help,
		'target=s' => \$opt_target,
		'prefix=s' => \$prefix,
		'socket-wrapper' => \$opt_socket_wrapper,
		'socket-wrapper-pcap=s' => \$opt_socket_wrapper_pcap,
		'quick' => \$opt_quick,
		'one' => \$opt_one,
		'immediate' => \$opt_immediate,
		'expected-failures=s' => \$opt_expected_failures,
		'skip=s' => \$opt_skip,
		'srcdir=s' => \$srcdir,
		'builddir=s' => \$builddir,
		'verbose' => \$opt_verbose,
		'testenv' => \$opt_testenv,
		'ldap' => \$opt_ldap,
		'analyse-cmd=s' => \$opt_analyse_cmd,
	    );

exit(1) if (not $result);

ShowHelp() if ($opt_help);

my $tests = shift;

# quick hack to disable rpc validation when using valgrind - its way too slow
unless (defined($ENV{VALGRIND})) {
	$ENV{VALIDATE} = "validate";
}

my $old_pwd = "$RealBin/../..";
my $ldap = 0;
if (defined($ENV{TEST_LDAP})) {
	$ldap = ($ENV{TEST_LDAP} eq "yes");
}
if (defined($opt_ldap)) {
	$ldap = $opt_ldap;
}

my $torture_maxtime = ($ENV{TORTURE_MAXTIME} or 1200);
if ($ldap) {
	# LDAP is slow
	$torture_maxtime *= 2;
}

$prefix =~ s+//+/+;
$ENV{PREFIX} = $prefix;

$ENV{SRCDIR} = $srcdir;

my $testsdir = "$srcdir/script/tests";

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

my @torture_options = ();

if ($opt_socket_wrapper_pcap) {
	$ENV{SOCKET_WRAPPER_PCAP_FILE} = $opt_socket_wrapper_pcap;
	# Socket wrapper pcap implies socket wrapper
	$opt_socket_wrapper = 1;
}

my $socket_wrapper_dir;
if ($opt_socket_wrapper) 
{
	$socket_wrapper_dir = SocketWrapper::setup_dir("$prefix/w");
	print "SOCKET_WRAPPER_DIR=$socket_wrapper_dir\n";
}

my $target;

if ($opt_target eq "samba4") {
	$target = new Samba4("$srcdir/bin", $ldap, "$srcdir/setup");
} elsif ($opt_target eq "samba3") {
	$target = new Samba3("$srcdir/bin", "$srcdir/setup");
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

my $testenv_vars;
$testenv_vars = $target->provision("dc", "$prefix/dc");

foreach (keys %$testenv_vars) { $ENV{$_} = $testenv_vars->{$_}; }

SocketWrapper::set_default_iface(1);
$target->check_or_start($testenv_vars, $socket_wrapper_dir, 
	($ENV{SMBD_MAX_TIME} or 5400));

SocketWrapper::set_default_iface(6);

my $interfaces = join(',', ("127.0.0.6/8", 
		                 "127.0.0.7/8",
						 "127.0.0.8/8",
						 "127.0.0.9/8",
						 "127.0.0.10/8",
						 "127.0.0.11/8"));

push (@torture_options, "--option=interfaces=$interfaces");
push (@torture_options, $testenv_vars->{CONFIGURATION});
# ensure any one smbtorture call doesn't run too long
push (@torture_options, "--maximum-runtime=$torture_maxtime");
push (@torture_options, "--target=$opt_target");
push (@torture_options, "--option=torture:progress=no") if ($from_build_farm);
push (@torture_options, "--format=subunit");
push (@torture_options, "--option=torture:quick=yes") if ($opt_quick);

$ENV{TORTURE_OPTIONS} = join(' ', @torture_options);
print "OPTIONS $ENV{TORTURE_OPTIONS}\n";

my @todo = ();

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
		push (@todo, [$name, $env, $cmdline]) 
			if (not defined($tests) or $name =~ /$tests/);
	} else {
		print;
	}
}
close(IN) or die("Error creating recipe");

$target->wait_for_start();

# start off with 0 failures
$ENV{failed} = 0;

my $suitestotal = $#todo + 1;
my $i = 0;
$| = 1;

# The Kerberos tests fail if this variable is set.
delete $ENV{DOMAIN};

if ($opt_testenv) {
	my $term = ($ENV{TERM} or "xterm");
	system("$term -e 'echo -e \"Welcome to the Samba4 Test environment
This matches the client environment used in make test
smbd is pid `cat \$PIDDIR/smbd.pid`

Some useful environment variables:
AUTH=\$AUTH
TORTURE_OPTIONS=\$TORTURE_OPTIONS
CONFIGURATION=\$CONFIGURATION
SERVER=\$SERVER
NETBIOSNAME=\$NETBIOSNAME\" && bash'");
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

		$target->setup_env($envname);

		if ($from_build_farm) {
			run_test_buildfarm($name, $cmd, $i, $suitestotal);
		} else {
			run_test_plain($name, $cmd, $i, $suitestotal);
		}

		if (defined($opt_analyse_cmd)) {
			system("$opt_analyse_cmd \"$name\"");
		}
	}
}

print "\n";

my $failed = $target->stop();

my $end = time();
my $duration = ($end-$start);
my $numfailed = $#$suitesfailed+1;
if ($numfailed == 0) {
	my $ok = $statistics->{TESTS_EXPECTED_OK} + $statistics->{TESTS_EXPECTED_FAIL};
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
	} else {
		print <<EOF	    
************************
*** TESTSUITE FAILED ***
************************
EOF
;
	}
}
print "DURATION: $duration seconds\n";

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
