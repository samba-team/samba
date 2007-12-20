#!/usr/bin/perl

package output::buildfarm;

use Exporter;
@ISA = qw(Exporter);

use strict;

sub new($$$$) {
	my ($class, $statistics) = @_;
	my $self = {
		statistics => $statistics,
		test_output => {}
	};
	bless($self, $class);
}

sub start_testsuite($$$)
{
	my ($self, $name, $state) = @_;
	my $out = "";

	my $duration = $state->{START_TIME} - $self->{statistics}->{START_TIME};
	$out .= "--==--==--==--==--==--==--==--==--==--==--\n";
	$out .= "Running test $name (level 0 stdout)\n";
	$out .= "--==--==--==--==--==--==--==--==--==--==--\n";
	$out .= scalar(localtime())."\n";
	$out .= "SELFTEST RUNTIME: " . $duration . "s\n";
	$out .= "NAME: $name\n";
	$out .= "CMD: $state->{CMD}\n";

	$self->{test_output}->{$name} = "";

	print $out;
}

sub output_msg($$$)
{
	my ($self, $state, $output) = @_;

	$self->{test_output}->{$state->{NAME}} .= $output;
}

sub control_msg($$$)
{
	my ($self, $state, $output) = @_;

	$self->{test_output}->{$state->{NAME}} .= $output;
}

sub end_testsuite($$$$$$$)
{
	my ($self, $name, $state, $result, $unexpected, $reason) = @_;
	my $out = "";

	$out .= "TEST RUNTIME: " . (time() - $state->{START_TIME}) . "s\n";

	if (not $unexpected) {
		$out .= "ALL OK\n";
	} else {
		$out .= "ERROR: $reason\n";
		$out .= $self->{test_output}->{$name};
	}

	$out .= "PCAP FILE: $state->{PCAP_FILE}\n" if defined($state->{PCAP_FILE});

	$out .= "==========================================\n";
	if (not $unexpected) {
		$out .= "TEST PASSED: $name\n";
	} else {
		$out .= "TEST FAILED: $name (status $reason)\n";
	}
	$out .= "==========================================\n";

	print $out;
}

sub start_test($$$$)
{
	my ($self, $state, $parents, $testname) = @_;

	if ($#$parents == -1) {
		$self->start_testsuite($testname, $state);
	}
}

sub end_test($$$$$$)
{
	my ($self, $state, $parents, $testname, $result, $unexpected, $reason) = @_;

	if ($unexpected) {
		$self->{test_output}->{$state->{NAME}} .= "UNEXPECTED($result): $testname\n";
	}

	if ($#$parents == -1) {
		$self->end_testsuite($testname, $state, $result, $unexpected, $reason); 
	}
}

sub summary($)
{
	my ($self) = @_;
}

sub skip_testsuite($$$$)
{
	my ($self, $name, $reason) = @_;

	print "SKIPPED: $name\n";
}

1;
