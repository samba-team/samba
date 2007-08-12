#!/usr/bin/perl

package output::buildfarm;

use Exporter;
@ISA = qw(Exporter);

use strict;

sub new($$) {
	my ($class) = @_;
	my $self = { 
		start => time(),
		test_output => {}
	};
	bless($self, $class);
}

sub start_testsuite($$)
{
	my ($self, $state) = @_;
	my $out = "";

	$out .= "--==--==--==--==--==--==--==--==--==--==--\n";
	$out .= "Running test $state->{NAME} (level 0 stdout)\n";
	$out .= "--==--==--==--==--==--==--==--==--==--==--\n";
	$out .= scalar(localtime())."\n";
	$out .= "SELFTEST RUNTIME: " . ($state->{START_TIME} - $self->{START_TIME}) . "s\n";
	$out .= "NAME: $state->{NAME}\n";
	$out .= "CMD: $state->{CMD}\n";

	$self->{test_output}->{$state->{NAME}} = "";

	print $out;
}

sub output_msg($$$)
{
	my ($self, $state, $output) = @_;

	$self->{test_output}->{$state->{NAME}} .= $output;
}

sub end_testsuite($$$$$)
{
	my ($self, $state, $expected_ret, $ret, $envlog) = @_;
	my $out = "";

	$out .= "TEST RUNTIME: " . (time() - $state->{START_TIME}) . "s\n";

	if ($ret == $expected_ret) {
		$out .= "ALL OK\n";
	} else {
		$out .= "ERROR: $ret";
		$out .= $self->{test_output}->{$state->{NAME}};
	}

	$out .= "PCAP FILE: $state->{PCAP_FILE}\n" if defined($state->{PCAP_FILE});

	$out .= $envlog;

	$out .= "==========================================\n";
	if ($ret == $expected_ret) {
		$out .= "TEST PASSED: $state->{NAME}\n";
	} else {
		$out .= "TEST FAILED: $state->{NAME} (status $ret)\n";
	}
	$out .= "==========================================\n";

	print $out;
}

sub start_test($$$)
{
	my ($self, $state, $testname) = @_;
}

sub end_test($$$$$)
{
	my ($self, $state, $testname, $result, $expected) = @_;
}

sub summary($)
{
	my ($self) = @_;
}

sub missing_env($$$)
{
	my ($self, $name, $envname) = @_;

	print "FAIL: $name (ENV[$envname] not available!)\n";
}

sub skip_testsuite($$)
{
	my ($self, $name) = @_;

	print "SKIPPED: $name\n";
}

1;
