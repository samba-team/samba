#!/usr/bin/perl -w

use strict;
use Getopt::Long;

my $opt_hostname = `hostname`;
chomp $opt_hostname;
my $opt_realm;
my $opt_domain;
my $opt_adminpass;
my $dnsname;
my $basedn;

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

# generate a random password. Poor algorithm :(
sub randpass()
{
	my $pass = "";
	my $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ%\$!~";
	for (my $i=0;$i<8;$i++) {
		my $c = int(rand(length($chars)));
		$pass .= substr($chars, $c, 1);
	}
	return $pass;
}

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
		return $opt_domain;
	}

	if ($var eq "REALM") {
		return $opt_realm;
	}

	if ($var eq "HOSTNAME") {
		return $opt_hostname;
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

	if ($var eq "ADMINPASS") {
		return $opt_adminpass;
	}

	if ($var eq "NTTIME") {
		return "" . nttime();
	}

	die "ERROR: Uknown substitution variable $var\n";
}

#####################################################################
# write a string into a file
sub FileSave($$)
{
    my($filename) = shift;
    my($v) = shift;
    local(*FILE);
    open(FILE, ">$filename") || die "can't open $filename";    
    print FILE $v;
    close(FILE);
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

#######################################################################
# add a foreign security principle
sub add_foreign($$)
{
	my $sid = shift;
	my $desc = shift;
	return "
dn: CN=$sid,CN=ForeignSecurityPrincipals,\${BASEDN}
objectClass: top
objectClass: foreignSecurityPrincipal
cn: $sid
description: $desc
distinguishedName: CN=$sid,CN=ForeignSecurityPrincipals,\${BASEDN}
instanceType: 4
whenCreated: \${LDAPTIME}
whenChanged: \${LDAPTIME}
uSNCreated: 1
uSNChanged: 1
showInAdvancedViewOnly: TRUE
name: $sid
objectGUID: \${NEWGUID}
objectSid: $sid
objectCategory: CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,\${BASEDN}

";
}

############################################
# show some help
sub ShowHelp()
{
	print "
Samba4 provisioning

provision.pl [options]
  --realm     REALM       set realm
  --domain    DOMAIN      set domain
  --hostname  HOSTNAME    set hostname
  --adminpass PASSWORD    choose admin password (otherwise random)

You must provide at least a realm and domain

";
	exit(1);
}

my $opt_help;

GetOptions(
	    'help|h|?' => \$opt_help, 
	    'realm=s' => \$opt_realm,
	    'domain=s' => \$opt_domain,
	    'hostname=s' => \$opt_hostname,
	    'adminpass=s' => \$opt_adminpass,
	    );

if ($opt_help || 
    !$opt_realm ||
    !$opt_domain ||
    !$opt_hostname) {
	ShowHelp();
}

print "Provisioning host '$opt_hostname' for domain '$opt_domain' in realm '$opt_realm'\n";

print "generating ldif ...\n";

$dnsname = "$opt_hostname.$opt_realm";
$basedn = "DC=" . join(",DC=", split(/\./, $opt_realm));

my $data = FileLoad("provision.ldif") || die "Unable to load provision.ldif\n";

$data .= add_foreign("S-1-5-7", "Anonymous");
$data .= add_foreign("S-1-5-18", "System");
$data .= add_foreign("S-1-5-11", "Authenticated Users");

if (!$opt_adminpass) {
	$opt_adminpass = randpass();
	print "chose random Administrator password '$opt_adminpass'\n";
}

my $res = "";

print "applying substitutions ...\n";

while ($data =~ /(.*?)\$\{(\w*)\}(.*)/s) {
	my $sub = substitute($2);
	$res .= "$1$sub";
	$data = $3;
}
$res .= $data;

print "saving ldif to newsam.ldif ...\n";

FileSave("newsam.ldif", $res);

unlink("newsam.ldb");

print "creating newsam.ldb ...\n";

# allow provisioning to be run from the source directory
$ENV{"PATH"} .= ":bin";

system("ldbadd -H newsam.ldb newsam.ldif");

print "done

Please move newsam.ldb to sam.ldb in the lib/private/ directory of your
Samba4 installation
";

