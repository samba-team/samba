#!/usr/bin/perl
# Filter a subunit stream
# Copyright (C) Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later

package Subunit::Filter;

use strict;

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

sub find_in_list($$)
{
	my ($list, $fullname) = @_;

	foreach (@$list) {
		if ($fullname =~ /$$_[0]/) {
			 return ($$_[1]) if ($$_[1]);
			 return "";
		}
	}

	return undef;
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

sub start_test($$)
{
	my ($self, $testname) = @_;

	if (defined($self->{prefix})) {
		$testname = $self->{prefix}.$testname;
	}

	Subunit::start_test($testname);
}

sub end_test($$$$$)
{
	my ($self, $testname, $result, $unexpected, $reason) = @_;

	if (defined($self->{prefix})) {
		$testname = $self->{prefix}.$testname;
	}

	if (($result eq "fail" or $result eq "failure") and not $unexpected) { $result = "xfail"; }
	my $xfail_reason = find_in_list($self->{expected_failures}, $testname);
	if (defined($xfail_reason) and ($result eq "fail" or $result eq "failure")) {
		$result = "xfail";
		$reason .= $xfail_reason;
	}

	Subunit::end_test($testname, $result, $reason);
}

sub skip_testsuite($;$)
{
	Subunit::skip_testsuite(@_);
}

sub start_testsuite($;$)
{
	my ($self, $name) = @_;
	Subunit::start_testsuite($name);
}

sub end_testsuite($$;$)
{
	my ($self, $name, $result, $reason) = @_;
	Subunit::end_testsuite($name, $result, $reason);
}

sub testsuite_count($$)
{
	my ($self, $count) = @_;
	Subunit::testsuite_count($count);
}

sub new {
	my ($class, $prefix, $expected_failures) = @_;

	my $self = { 
		prefix => $prefix,
		expected_failures => $expected_failures,
	};
	bless($self, $class);
}

1;
