#!/usr/bin/perl -w

use strict;
use Getopt::Long;

my $opt_hostname = `hostname`;
chomp $opt_hostname;
my $opt_realm;
my $opt_domain;
my $opt_netbiosname;
my $dnsdomain;
my $dnsname;
my $basedn;

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

	if ($var eq "NETBIOSNAME") {
		return $opt_netbiosname;
	}

	if ($var eq "DNSDOMAIN") {
		return $dnsdomain;
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

############################################
# show some help
sub ShowHelp()
{
	print "
Samba4 provisioning

rootdse.pl [options]
  --realm       REALM        set realm
  --domain      DOMAIN       set domain
  --hostname    HOSTNAME     set hostname
  --netbiosname NETBIOSNAME  choose admin password (otherwise random)

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
	    'netbiosname=s' => \$opt_netbiosname,
	    );

if ($opt_help || 
    !$opt_realm ||
    !$opt_domain ||
    !$opt_hostname ||
    !$opt_netbiosname) {
	ShowHelp();
}

$opt_realm=uc($opt_realm);
$opt_domain=uc($opt_domain);
$opt_hostname=uc($opt_hostname);
$opt_netbiosname=uc($opt_netbiosname);

print "Provisioning host '$opt_hostname' with netbios name '$opt_netbiosname' for domain '$opt_domain' in realm '$opt_realm'\n";

print "generating ldif ...\n";

$dnsdomain = lc($opt_realm);
$dnsname = lc($opt_hostname).".".$dnsdomain;
$basedn = "DC=" . join(",DC=", split(/\./, $opt_realm));

my $data = FileLoad("rootdse.ldif") || die "Unable to load rootdse.ldif\n";

my $res = "";

print "applying substitutions ...\n";

while ($data =~ /(.*?)\$\{(\w*)\}(.*)/s) {
	my $sub = substitute($2);
	$res .= "$1$sub";
	$data = $3;
}
$res .= $data;

print "saving ldif to newrootdse.ldif ...\n";

FileSave("newrootdse.ldif", $res);

unlink("newrootdse.ldb");

print "creating newrootdse.ldb ...\n";

# allow provisioning to be run from the source directory
$ENV{"PATH"} .= ":bin";

system("ldbadd -H newrootdse.ldb newroodse.ldif");

print "done

Please move newrootdse.ldb to rootdse.ldb in the lib/private/ directory of your
Samba4 installation
";

