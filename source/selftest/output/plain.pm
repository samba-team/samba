#!/usr/bin/perl

package output::plain;
use Exporter;
@ISA = qw(Exporter);

use strict;

sub new($$$$) {
	my ($class, $verbose, $immediate, $statistics) = @_;
	my $self = { 
		verbose => $verbose, 
		immediate => $immediate, 
		statistics => $statistics,
		test_output => {},
		suitesfailed => [],
		start => time()
	};
	bless($self, $class);
}

sub output_msg($$$);

sub start_testsuite($$)
{
	my ($self, $state) = @_;
	my $out = "";

	my $duration = $state->{START_TIME} - $self->{statistics}->{START_TIME};
	$out .= "[$state->{INDEX}/$state->{TOTAL} in ".$duration."s";
	$out .= sprintf(", %d errors", $self->{statistics}->{SUITES_FAIL}) if ($self->{statistics}->{SUITES_FAIL} > 0);
	$out .= "] $state->{NAME}\n", 

	$self->{test_output}->{$state->{NAME}} = "" unless($self->{verbose});

	$self->output_msg($state, "CMD: $state->{CMD}\n");

	print $out;
}

sub output_msg($$$)
{
	my ($self, $state, $output) = @_;

	if ($self->{verbose}) {
		print $output;
	} else {
		$self->{test_output}->{$state->{NAME}} .= $output;
	}
}

sub end_testsuite($$$$$)
{
	my ($self, $state, $expected_ret, $ret, $envlog) = @_;
	my $out = "";

	if ($ret != $expected_ret) {
		$self->output_msg($state, "ERROR: $ret\n");
	}

	if ($ret != $expected_ret and $self->{immediate} and not $self->{verbose}) {
		$out .= $self->{test_output}->{$state->{NAME}};
	}

	print $out;
}

sub start_test($$)
{
	my ($state, $testname) = @_;
}

sub end_test($$$$)
{
	my ($state, $testname, $result, $unexpected) = @_;
}

sub summary($)
{
	my ($self) = @_;

	if (not $self->{immediate} and not $self->{verbose}) {
		foreach (@{$self->{suitesfailed}}) {
			print "===============================================================================\n";
			print "FAIL: $_\n";
			print $self->{test_output}->{$_};
			print "\n";
		}
	}

	print "FAILED ($self->{statistics}->{TESTS_UNEXPECTED_FAIL} failures and $self->{statistics}->{TESTS_ERROR} errors in $self->{statistics}->{SUITES_FAIL} testsuites)\n";
}

sub missing_env($$$)
{
	my ($self, $name, $envname) = @_;

	print "FAIL: $name (ENV[$envname] not available!)\n";
}

1;
