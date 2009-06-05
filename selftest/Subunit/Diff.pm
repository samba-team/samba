#!/usr/bin/perl
# Diff two subunit streams
# Copyright (C) Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later

package Subunit::Diff;

use strict;

use Subunit qw(parse_results);

sub control_msg() { }
sub report_time($$) { }

sub output_msg($$)
{
	my ($self, $msg) = @_;

	# No output for now, perhaps later diff this as well ?
}

sub start_test($$)
{
	my ($self, $testname) = @_;
}

sub end_test($$$$$)
{
	my ($self, $testname, $result, $unexpected, $reason) = @_;

	$self->{$testname} = $result;
}

sub skip_testsuite($;$) { } 
sub start_testsuite($;$) { }
sub end_testsuite($$;$) { }
sub testsuite_count($$) { }

sub new {
	my ($class) = @_;

	my $self = { 
	};
	bless($self, $class);
}

sub diff($$)
{
	my ($fh1, $fh2) = @_;
	my $ret = {};
	my $statistics = {
		TESTS_UNEXPECTED_OK => 0,
		TESTS_EXPECTED_OK => 0,
		TESTS_UNEXPECTED_FAIL => 0,
		TESTS_EXPECTED_FAIL => 0,
		TESTS_ERROR => 0,
		TESTS_SKIP => 0,
	};
	my $old = new Subunit::Diff();
	parse_results($old, $statistics, $fh1);
	my $new = new Subunit::Diff();
	parse_results($new, $statistics, $fh2);

	foreach my $testname (keys %$old) {
		if ($new->{$testname} ne $old->{$testname}) {
			$ret->{$testname} = [$old->{$testname}, $new->{$testname}];
		}
	}

	return $ret;
}

1;
