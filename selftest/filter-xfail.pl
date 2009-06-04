#!/usr/bin/perl
# Fix fail -> xfail in subunit streams based on a list of regular expressions
# Copyright (C) Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later

=pod

=head1 NAME

filter-xfail - Filter known failures in a subunit stream

=head1 SYNOPSIS

filter-xfail --help

filter-xfail --known-failures=FILE < in-stream > out-stream

=head1 DESCRIPTION

Simple Subunit stream filter that will change failures to known failures 
based on a list of regular expressions.

=head1 OPTIONS

=over 4

=item I<--expected-failures>

Specify a file containing a list of tests that are expected to fail. Failures 
for these tests will be counted as successes, successes will be counted as 
failures.

The format for the file is, one entry per line:

TESTSUITE-NAME.TEST-NAME

The reason for a test can also be specified, by adding a hash sign (#) and the reason 
after the test name.

=head1 LICENSE

selftest is licensed under the GNU General Public License L<http://www.gnu.org/licenses/gpl.html>.


=head1 AUTHOR

Jelmer Vernooij

=cut


use Getopt::Long;
use strict;
use FindBin qw($RealBin $Script);
use lib "$RealBin";
use Subunit qw(parse_results);

my $opt_expected_failures = undef;
my $opt_help = 0;
my @expected_failures = ();

my $result = GetOptions(
		'expected-failures=s' => \$opt_expected_failures,
		'help' => \$opt_help,
	);
exit(1) if (not $result);

if ($opt_help) {
	print "Usage: filter-xfail [--expected-failures=FILE]... < instream > outstream\n";
	exit(0);
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

my $statistics = {
	SUITES_FAIL => 0,

	TESTS_UNEXPECTED_OK => 0,
	TESTS_EXPECTED_OK => 0,
	TESTS_UNEXPECTED_FAIL => 0,
	TESTS_EXPECTED_FAIL => 0,
	TESTS_ERROR => 0,
	TESTS_SKIP => 0,
};

sub control_msg()
{
	# We regenerate control messages, so ignore this
}

sub report_time($$)
{
	my ($self, $time) = @_;
	Subunit::report_time($time);
}

sub output_msg($$)
{
	my ($self, $msg) = @_;
	print $msg;
}

sub start_test($$$)
{
	my ($self, $parents, $testname) = @_;

	Subunit::start_test($testname);
}

sub end_test($$$$$)
{
	my ($self, $parents, $testname, $result, $unexpected, $reason) = @_;

	if (($result eq "fail" or $result eq "failure") and not $unexpected) { $result = "xfail"; }
	my $fullname = join(".", @$parents) . ".$testname";
	if (expecting_failure($fullname) and ($result eq "fail" or $result eq "failure")) {
		$result = "xfail";
	}

	Subunit::end_test($testname, $result, $reason);
}

my $msg_ops = {};
bless $msg_ops;

parse_results($msg_ops, $statistics, *STDIN, []);

0;
