#!/usr/bin/perl -w

use strict;

my $hostname = `hostname`;
chomp $hostname;
my $realm = "bludom.tridgell.net";
my $domain = "BLUDOM";
my $dnsname = "$hostname.$realm";

my $basedn = "DC=" . join(",DN=", split(/\./, $realm));

# return the current NTTIME as an integer
sub nttime()
{
	my $t = time();
	$t += (369.0*365.25*24*60*60-(3.0*24*60*60+6.0*60*60));
	$t *= 1.0e7;
	return sprintf("%lld", $t);
}

# generate a random guid. Not a good algorithm.
sub randguid()
{
	my $r1 = int(rand(2**32));
	my $r2 = int(rand(2**16));
	my $r3 = int(rand(2**16));
	my $r4 = int(rand(2**16));
	my $r5 = int(rand(2**32));
	return sprintf("%08x-%04x-%04x-%04x-%08x", $r1, $r2, $r3, $r4, $r5);
}

sub randsid()
{
	return sprintf("S-1-5-21-%d-%d-%d", 
		       int(rand(10**8)), int(rand(10**8)), int(rand(10**8)));
}

#######################
# substitute a single variable
sub substitute($)
{
	my $var = shift;

	if ($var eq "BASEDN") {
		return $basedn;
	}

	if ($var eq "DOMAINSID") {
		return randsid();
	}

	if ($var eq "DOMAIN") {
		return $domain;
	}

	if ($var eq "HOSTNAME") {
		return $hostname;
	}

	if ($var eq "DNSNAME") {
		return $dnsname;
	}

	if ($var eq "LDAPTIME") {
		return "20040408072022.0Z";
	}

	if ($var eq "NEWGUID") {
		return randguid();
	}

	if ($var eq "NTTIME") {
		return "" . nttime();
	}

	die "ERROR: Uknown substitution variable $var\n";
}

#####################################################################
# read a file into a string
sub FileLoad($)
{
    my($filename) = shift;
    local(*INPUTFILE);
    open(INPUTFILE, $filename) || return undef;
    my($saved_delim) = $/;
    undef $/;
    my($data) = <INPUTFILE>;
    close(INPUTFILE);
    $/ = $saved_delim;
    return $data;
}


my $data = FileLoad("provision.ldif") || die "Unable to load provision.ldif\n";

my $res = "";

while ($data =~ /(.*?)\$\{(\w*)\}(.*)/s) {
	my $sub = substitute($2);
	$res .= "$1$sub";
	$data = $3;
}

print $res . $data;

