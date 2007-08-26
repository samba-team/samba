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
		local_statistics => {},
		msg => ""
	};

	link("selftest/output/testresults.css", "$dirname/testresults.css");

	open(INDEX, ">$dirname/index.html");

	print INDEX "<html lang=\"en\">\n";
	print INDEX "<head>\n";
	print INDEX "  <title>Samba Testsuite Run</title>\n";
	print INDEX "  <link rel=\"stylesheet\" type=\"text/css\" href=\"testresults.css\"/>\n";
	print INDEX "</head>\n";
	print INDEX "<body>\n";
	print INDEX "<table width=\"100%\" border=\"0\" cellspacing=\"0\">\n";
	print INDEX "  <tr><td class=\"title\">Samba Testsuite Run</td></tr>\n";
	print INDEX "  <tr><td>\n";
	print INDEX "  <center>";
	print INDEX "  <table>\n";
	print INDEX "  <tr>\n";
	print INDEX "    <td class=\"tableHead\">Test</td>\n";
	print INDEX "    <td class=\"tableHead\">Environment</td>\n";
	print INDEX "    <td class=\"tableHead\">Result</td>\n";
	print INDEX "  </tr>\n";

	bless($self, $class);
}

sub output_msg($$$);

sub start_testsuite($$)
{
	my ($self, $state) = @_;

	$self->{local_statistics} = {
		success => 0,
		skip => 0,
		error => 0,
		failure => 0
	};

	$state->{HTMLFILE} = "$state->{NAME}.html";
	$state->{HTMLFILE} =~ s/[:\t\n \/]/_/g;

	open(TEST, ">$self->{dirname}/$state->{HTMLFILE}") or die("Unable to open $state->{HTMLFILE} for writing");

	my $title = "Test Results for $state->{NAME}";

	print TEST "<html lang=\"en\">\n";
	print TEST "<head>\n";
	print TEST "  <title>$title</title>\n";
	print TEST "  <link rel=\"stylesheet\" type=\"text/css\" href=\"testresults.css\"/>\n";
	print TEST "</head>\n";
	print TEST "<body>\n";
	print TEST "<table width=\"100%\" border=\"0\" cellspacing=\"0\">\n";
	print TEST "  <tr><td class=\"title\">$title</td></tr>\n";
	print TEST "  <tr><td>\n";
	print TEST "  <table>\n";
}

sub control_msg($$$)
{
	my ($self, $state, $output) = @_;

	$self->{msg} .=  "<span class=\"control\">$output<br/></span>\n";
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

	print TEST "</table>\n";

	print TEST "<div class=\"duration\">Duration: " . (time() - $state->{START_TIME}) . "s</div>\n";
	print TEST "</body>\n";
	print TEST "</html>\n";

	close(TEST);

	print INDEX "<tr>\n";
	print INDEX "  <td class=\"testSuite\"><a href=\"$state->{HTMLFILE}\">$state->{NAME}</a></td>\n";
	print INDEX "  <td class=\"environment\">$state->{ENVNAME}</td>\n";
	my $st = $self->{local_statistics};

	if ($ret == $expected_ret) {
		print INDEX "  <td class=\"resultOk\">";
	} else {
		print INDEX "  <td class=\"resultFailure\">";
	}

	my $l = 0;
	if ($st->{success} > 0) {
		print INDEX "$st->{success} ok";
		$l++;
	}
	if ($st->{skip} > 0) {
		print INDEX ", " if ($l);
		print INDEX "$st->{skip} skipped";
		$l++;
	}
	if ($st->{failure} > 0) {
		print INDEX ", " if ($l);
		print INDEX "$st->{failure} failures";
		$l++;
	}
	if ($st->{error} > 0) {
		print INDEX ", " if ($l);
		print INDEX "$st->{error} errors";
		$l++;
	}

	if ($l == 0) {
		if ($ret == $expected_ret) {
			print INDEX "OK";
		} else {
			print INDEX "FAIL";
		}
	}

	print INDEX "</td>";
		
	print INDEX "</tr>\n";
}

sub start_test($$$)
{
	my ($self, $state, $testname) = @_;

	$self->{active_test} = $testname;
	$self->{msg} = "";
}

sub end_test($$$$$$)
{
	my ($self, $state, $testname, $result, $unexpected, $reason) = @_;

	print TEST "<tr>";

	$self->{local_statistics}->{$result}++;

	if ($result eq "skip") {
		print TEST "<td class=\"outputSkipped\">\n";
	} elsif ($unexpected) {
		print TEST "<td class=\"outputFailure\">\n";
	} else {
		print TEST "<td class=\"outputOk\">\n";
	}

	print TEST "<h3>$testname</h3>\n";

	print TEST $self->{msg};

	if (defined($reason)) {
		print TEST "<div class=\"reason\">$reason</div>\n";
	}

	print TEST "</td></tr>\n";

	$self->{active_test} = undef;
}

sub summary($)
{
	my ($self) = @_;

	my $st = $self->{statistics};
	print INDEX "<tr>\n";
	print INDEX "  <td class=\"testSuiteTotal\">Total</td>\n";
	print INDEX "  <td></td>\n";

	if ($st->{SUITES_FAIL} == 0) {
		print INDEX "  <td class=\"resultOk\">";
	} else {
		print INDEX "  <td class=\"resultFailure\">";
	}
	print INDEX ($st->{TESTS_EXPECTED_OK} + $st->{TESTS_UNEXPECTED_OK}) + " ok";
	if ($st->{TESTS_UNEXPECTED_OK} > 0) {
		print INDEX " ($st->{TESTS_UNEXPECTED_OK} unexpected)";
	}
	if ($st->{TESTS_SKIP} > 0) {
		print INDEX ", $st->{TESTS_SKIP} skipped";
	}
	print INDEX ", " . ($st->{TESTS_UNEXPECTED_FAIL} + $st->{TESTS_EXPECTED_FAIL}) . " failures";
	if ($st->{TESTS_UNEXPECTED_OK} > 0) {
		print INDEX " ($st->{TESTS_EXPECTED_FAIL} expected)";
	}
	if ($st->{TESTS_ERROR} > 0) {
		print INDEX ", $st->{TESTS_ERROR} errors";
	}

	print INDEX "</td>";

	print INDEX "</tr>\n";

	print INDEX "</table>\n";
	print INDEX "</center>\n";
	print INDEX "</td></tr>\n";
	print INDEX "</table>\n";
	print INDEX "</body>\n";
	print INDEX "</html>\n";
	close(INDEX);
}

sub missing_env($$$)
{
	my ($self, $name, $envname) = @_;

	print INDEX "<tr>\n";
	print INDEX "  <td class=\"testSuite\">$name</td>\n";
	print INDEX "  <td class=\"resultSkipped\" colspan=\"2\">SKIPPED - environment `$envname` not available!</td>\n";
	print INDEX "</tr>\n";
}

sub skip_testsuite($$)
{
	my ($self, $name) = @_;

	print INDEX "<tr>\n";
	print INDEX "  <td class=\"testSuite\">$name</td>\n";
	print INDEX "  <td class=\"resultSkipped\" colspan=\"2\">SKIPPED</td>\n";
	print INDEX "</tr>\n";
}

1;
