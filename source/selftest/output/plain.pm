#!/usr/bin/perl

package output::plain;
use Exporter;
@ISA = qw(Exporter);

use strict;

sub new($$$$$) {
	my ($class, $summaryfile, $verbose, $immediate, $statistics) = @_;
	my $self = { 
		verbose => $verbose, 
		immediate => $immediate, 
		statistics => $statistics,
		test_output => {},
		suitesfailed => [],
		skips => {},
		summaryfile => $summaryfile,
	};
	bless($self, $class);
}

sub output_msg($$$);

sub start_testsuite($$$)
{
	my ($self, $name, $state) = @_;
	my $out = "";

	my $duration = $state->{START_TIME} - $self->{statistics}->{START_TIME};
	$out .= "[$state->{INDEX}/$state->{TOTAL} in ".$duration."s";
	$out .= sprintf(", %d errors", $self->{statistics}->{SUITES_FAIL}) if ($self->{statistics}->{SUITES_FAIL} > 0);
	$out .= "] $name\n", 

	$self->{test_output}->{$name} = "" unless($self->{verbose});

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

sub control_msg($$$)
{
	my ($self, $state, $output) = @_;

	$self->output_msg($state, $output);
}

sub end_testsuite($$$$$$)
{
	my ($self, $name, $state, $expected_ret, $ret, $envlog) = @_;
	my $out = "";

	$self->output_msg($state, "ENVLOG: $envlog\n") if ($envlog ne "");

	if ($ret != $expected_ret) {
		$self->output_msg($state, "ERROR: $ret\n");
	}

	if ($ret != $expected_ret and $self->{immediate} and not $self->{verbose}) {
		$out .= $self->{test_output}->{$name};
		push (@{$self->{suitesfailed}}, $name);
	}

	print $out;
}

sub start_test($$)
{
	my ($state, $testname) = @_;
}

sub end_test($$$$$$)
{
	my ($self, $state, $testname, $result, $unexpected, $reason) = @_;
	my $append = "";

	unless ($unexpected) {
		$self->{test_output}->{$state->{NAME}} = "";
		return;
	}

	$append = "UNEXPECTED($result): $testname\n";

	$self->{test_output}->{$state->{NAME}} .= $append;

	if ($self->{immediate} and not $self->{verbose}) {
		print $self->{test_output}->{$state->{NAME}};
		$self->{test_output}->{$state->{NAME}} = "";
	}
}

sub summary($)
{
	my ($self) = @_;

	open(SUMMARY, ">$self->{summaryfile}");

	if ($#{$self->{suitesfailed}} > -1) {
		print SUMMARY "= Failed tests =\n";

		foreach (@{$self->{suitesfailed}}) {
			print SUMMARY "== $_ ==\n";
			print SUMMARY $self->{test_output}->{$_}."\n\n";
		}

		print SUMMARY "\n";
	}

	if (not $self->{immediate} and not $self->{verbose}) {
		foreach (@{$self->{suitesfailed}}) {
			print "===============================================================================\n";
			print "FAIL: $_\n";
			print $self->{test_output}->{$_};
			print "\n";
		}
	}

	print SUMMARY "= Skipped tests =\n";
	foreach my $reason (keys %{$self->{skips}}) {
		print SUMMARY "$reason\n";
		foreach my $name (@{$self->{skips}->{$reason}}) {
			print SUMMARY "\t$name\n";
		}
		print SUMMARY "\n";
	}
	close(SUMMARY);

	print "\nA summary with detailed informations can be found in:\n  $self->{summaryfile}\n";

	if ($self->{statistics}->{SUITES_FAIL} == 0) {
		my $ok = $self->{statistics}->{TESTS_EXPECTED_OK} + 
				 $self->{statistics}->{TESTS_EXPECTED_FAIL};
		print "\nALL OK ($ok tests in $self->{statistics}->{SUITES_OK} testsuites)\n";
	} else {
		print "\nFAILED ($self->{statistics}->{TESTS_UNEXPECTED_FAIL} failures and $self->{statistics}->{TESTS_ERROR} errors in $self->{statistics}->{SUITES_FAIL} testsuites)\n";
	}

}

sub skip_testsuite($$)
{
	my ($self, $name, $reason) = @_;

	push (@{$self->{skips}->{$reason}}, $name);
}

1;
