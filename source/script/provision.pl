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
	my $r6 = int(rand(2**16));
	return sprintf("%08x-%04x-%04x-%04x-%08x%04x", $r1, $r2, $r3, $r4, $r5, $r6);
}

my $domainguid = randguid();

sub randsid()
{
	return sprintf("S-1-5-21-%d-%d-%d", 
		       int(rand(10**8)), int(rand(10**8)), int(rand(10**8)));
}

my $domainsid = randsid();

sub ldaptime()
{
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday) =  gmtime(time);
	return sprintf "%04u%02u%02u%02u%02u%02u.0Z",
	$year+1900, $mon+1, $mday, $hour, $min, $sec;
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
		return $domainsid;
	}

	if ($var eq "DOMAIN") {
		return $domain;
	}

	if ($var eq "REALM") {
		return $realm;
	}

	if ($var eq "HOSTNAME") {
		return $hostname;
	}

	if ($var eq "DNSNAME") {
		return $dnsname;
	}

	if ($var eq "LDAPTIME") {
		return ldaptime();
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
