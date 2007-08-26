#!/usr/bin/perl

package output::html;
use Exporter;
@ISA = qw(Exporter);

use strict;
use warnings;

sub new($$$$) {
	my ($class, $dirname, $statistics) = @_;
	my $self = { 
		dirname => $dirname,
		statistics => $statistics,
		active_test => undef,
		msg => ""
	};

	open(INDEX, ">$dirname/index.html");

	print INDEX "<html>\n";
	print INDEX "<body>\n";
	print INDEX "<table>\n";
	print INDEX "<tr><td>Test</td><td>Environment</td><td>Result</td><td>Duration</td></tr>\n";

	$self->{INDEX} = *INDEX;

	bless($self, $class);
}

sub output_msg($$$);

sub start_testsuite($$)
{
	my ($self, $state) = @_;

	$state->{HTMLFILE} = "$state->{NAME}.html";

	$state->{HTMLFILE} =~ s/[:\t\n ]/_/g;

	open(TEST, ">$self->{dirname}/$state->{HTMLFILE}");

	print TEST "<html>\n";
	print TEST "<body>\n";
}

sub output_msg($$$)
{
	my ($self, $state, $output) = @_;

	unless (defined($self->{active_test})) {
		print TEST "$output<br/>";
	} else {
		$self->{msg} .= "$output<br/>";
	}
}

sub end_testsuite($$$$$)
{
	my ($self, $state, $expected_ret, $ret, $envlog) = @_;

	print TEST "</body>\n";
	print TEST "</html>\n";

	close(TEST);

	print INDEX "<tr><td><a href=\"$state->{HTMLFILE}\">$state->{NAME}</a></td><td>$state->{ENVNAME}</td>";

	if ($ret == $expected_ret) {
		print INDEX "<td bgcolor=\"green\">OK</td>";
	} else {
		print INDEX "<td bgcolor=\"red\">FAIL</td>";
	}

	print INDEX "<td>" . (time() - $state->{START_TIME}) . "</td>\n";

	print INDEX "</tr>\n";
}

sub start_test($$$)
{
	my ($self, $state, $testname) = @_;

	print TEST "<h3>$testname</h3>\n";

	$self->{active_test} = $testname;
	$self->{msg} = "";
}

sub end_test($$$$$)
{
	my ($self, $state, $testname, $result, $unexpected) = @_;

	if ($result eq "skip") {
		print TEST "<div bgcolor=\"yellow\">\n";
	} elsif ($unexpected) {
		print TEST "<div bgcolor=\"red\">\n";
	}

	print TEST $self->{msg};

	print TEST "</div>\n";

	$self->{active_test} = undef;
}

sub summary($)
{
	my ($self) = @_;
	print INDEX "</table>\n";
	print INDEX "FAILED ($self->{statistics}->{TESTS_UNEXPECTED_FAIL} failures and $self->{statistics}->{TESTS_ERROR} errors in $self->{statistics}->{SUITES_FAIL} testsuites)\n";

	print INDEX "</body>\n";
	print INDEX "</html>\n";

	close(INDEX);
}

sub missing_env($$$)
{
	my ($self, $name, $envname) = @_;

	print "FAIL: $name (ENV[$envname] not available!)\n";
}

sub skip_testsuite($$)
{
	my ($self, $name) = @_;

	print INDEX "<tr><td>$name</td><td>N/A</td><td bgcolor=\"yellow\">SKIPPED</td><td>N/A</td></tr>\n";
}

1;
