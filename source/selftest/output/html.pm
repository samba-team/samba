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
	print INDEX "    <td class=\"tableHead\">Duration</td>\n";
	print INDEX "  </tr>\n";

	bless($self, $class);
}

sub output_msg($$$);

sub start_testsuite($$)
{
	my ($self, $state) = @_;

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
	print TEST "</body>\n";
	print TEST "</html>\n";

	close(TEST);

	print INDEX "<tr><td class=\"testSuite\"><a href=\"$state->{HTMLFILE}\">$state->{NAME}</a></td><td class=\"environment\">$state->{ENVNAME}</td>";

	if ($ret == $expected_ret) {
		print INDEX "<td class=\"resultOk\">OK</td>";
	} else {
		print INDEX "<td class=\"resultFailure\">FAIL</td>";
	}

	print INDEX "<td class=\"duration\">" . (time() - $state->{START_TIME}) . "</td>\n";

	print INDEX "</tr>\n";
}

sub start_test($$$)
{
	my ($self, $state, $testname) = @_;

	$self->{active_test} = $testname;
	$self->{msg} = "";
}

sub end_test($$$$$)
{
	my ($self, $state, $testname, $result, $unexpected) = @_;

	print TEST "<tr>";

	if ($result eq "skip") {
		print TEST "<td class=\"outputSkipped\">\n";
	} elsif ($unexpected) {
		print TEST "<td class=\"outputFailure\">\n";
	} else {
		print TEST "<td class=\"outputOk\">\n";
	}

	print TEST "<h3>$testname</h3>\n";

	print TEST $self->{msg};

	print TEST "</td></tr>\n";

	$self->{active_test} = undef;
}

sub summary($)
{
	my ($self) = @_;

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

	print "FAIL: $name (ENV[$envname] not available!)\n";
}

sub skip_testsuite($$)
{
	my ($self, $name) = @_;

	print INDEX "<tr><td class=\"testSuite\">$name</td><td class=\"environmentSkipped\">N/A</td><td class=\"resultSkipped\">SKIPPED</td><td class=\"durationSkipped\">N/A</td></tr>\n";
}

1;
