#!/usr/bin/perl -w

use strict;
use Socket;
use Getopt::Long;

my $opt_hostname = `hostname`;
chomp $opt_hostname;
my $opt_hostip;
my $opt_realm;
my $opt_domain;
my $opt_adminpass;
my $opt_nobody;
my $opt_nogroup;
my $opt_wheel;
my $opt_users;
my $dnsdomain;
my $netbiosname;
my $dnsname;
my $basedn;
my $defaultsite = "Default-First-Site-Name";
my $usn = 1;

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

my $opt_domainguid = randguid();
my $opt_hostguid = randguid();
my $opt_invocationid = randguid();

sub randsid()
{
	return sprintf("S-1-5-21-%d-%d-%d", 
		       int(rand(10**8)), int(rand(10**8)), int(rand(10**8)));
}

my $opt_domainsid = randsid();

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

my $joinpass = randpass();

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
		return $opt_domainsid;
	}

	if ($var eq "DOMAIN") {
		return $opt_domain;
	}

	if ($var eq "REALM") {
		return $opt_realm;
	}

	if ($var eq "DNSDOMAIN") {
		return $dnsdomain;
	}

	if ($var eq "HOSTNAME") {
		return $opt_hostname;
	}

	if ($var eq "NETBIOSNAME") {
		return $netbiosname;
	}

	if ($var eq "DNSNAME") {
		return $dnsname;
	}

	if ($var eq "HOSTIP") {
		return $opt_hostip;
	}

	if ($var eq "LDAPTIME") {
		return ldaptime();
	}

	if ($var eq "NEWGUID") {
		return randguid();
	}

	if ($var eq "NEWSCHEMAGUID") {
		return randguid();
	}

	if ($var eq "DOMAINGUID") {
		return $opt_domainguid;
	}

	if ($var eq "HOSTGUID") {
		return $opt_hostguid;
	}

	if ($var eq "INVOCATIONID") {
		return $opt_invocationid;
	}

	if ($var eq "DEFAULTSITE") {
		return $defaultsite;
	}

	if ($var eq "ADMINPASS") {
		return $opt_adminpass;
	}

	if ($var eq "RANDPASS") {
	    return randpass();
	}

	if ($var eq "JOINPASS") {
	    return $joinpass;
	}

	if ($var eq "NTTIME") {
		return "" . nttime();
	}

	if ($var eq "WHEEL") {
		return $opt_wheel;
	}

	if ($var eq "NOBODY") {
		return $opt_nobody;
	}

	if ($var eq "NOGROUP") {
		return $opt_nogroup;
	}

	if ($var eq "USERS") {
		return $opt_users;
	}

	if ($var eq "USN") {
		my $ret = $usn;
		$usn = $ret + 1;
		return $ret;
	}

	die "ERROR: Uknown substitution variable $var\n";
}


####################################################################
# substitute all variables in a string
sub apply_substitutions($)
{
	my $data = shift;
	my $res = "";
	while ($data =~ /(.*?)\$\{(\w*)\}(.*)/s) {
		my $sub = substitute($2);
		$res .= "$1$sub";
		$data = $3;
	}
	$res .= $data;
	return $res;
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
sub add_foreign($$$)
{
	my $sid = shift;
	my $desc = shift;
	my $unixname = shift;
	return "
dn: CN=$sid,CN=ForeignSecurityPrincipals,\${BASEDN}
objectClass: top
objectClass: foreignSecurityPrincipal
cn: $sid
description: $desc
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
unixName: $unixname

";
}

############################################
# show some help
sub ShowHelp()
{
	print "
Samba4 provisioning

provision.pl [options]
 --realm	REALM		set realm
 --domain	DOMAIN		set domain
 --domain-guid	GUID		set domainguid (otherwise random)
 --domain-sid	SID		set domainsid (otherwise random)
 --host-name	HOSTNAME	set hostname
 --host-ip	IPADDRESS	set ipaddress
 --host-guid	GUID		set hostguid (otherwise random)
 --invocationid	GUID		set invocationid (otherwise random)
 --adminpass	PASSWORD	choose admin password (otherwise random)
 --nobody	USERNAME	choose 'nobody' user
 --nogroup	GROUPNAME	choose 'nogroup' group
 --wheel	GROUPNAME	choose 'wheel' privileged group
 --users	GROUPNAME	choose 'users' group

You must provide at least a realm and domain

";
	exit(1);
}

my $opt_help;

GetOptions(
	    'help|h|?' => \$opt_help, 
	    'realm=s' => \$opt_realm,
	    'domain=s' => \$opt_domain,
	    'domain-guid=s' => \$opt_domainguid,
	    'domain-sid=s' => \$opt_domainsid,
	    'host-name=s' => \$opt_hostname,
	    'host-ip=s' => \$opt_hostip,
	    'host-guid=s' => \$opt_hostguid,
	    'invocationid=s' => \$opt_invocationid,
	    'adminpass=s' => \$opt_adminpass,
	    'nobody=s' => \$opt_nobody,
	    'nogroup=s' => \$opt_nogroup,
	    'wheel=s' => \$opt_wheel,
	    'users=s' => \$opt_users,
	    );

if ($opt_help || 
    !$opt_realm ||
    !$opt_domain ||
    !$opt_hostname) {
	ShowHelp();
}

$opt_realm=uc($opt_realm);
$opt_domain=uc($opt_domain);
$opt_hostname=lc($opt_hostname);
$netbiosname=uc($opt_hostname);

if (!$opt_hostip) {
	my $hip = gethostbyname($opt_hostname);
	if (defined $hip) {
		$opt_hostip = inet_ntoa($hip);
	} else {
		$opt_hostip = "<0.0.0.0>";
	}
}

print "Provisioning host '$opt_hostname'[$opt_hostip] for domain '$opt_domain' in realm '$opt_realm'\n";

if (!$opt_nobody) {
	if (defined getpwnam("nobody")) {
		$opt_nobody = "nobody";
	}
}

if (!$opt_nogroup) {
	if (defined getgrnam("nogroup")) {
		$opt_nogroup = "nogroup";
	} elsif (defined getgrnam("nobody")) {
		$opt_nogroup = "nobody";
	}
}

if (!$opt_wheel) {
	if (defined getgrnam("wheel")) {
		$opt_wheel = "wheel";
	} elsif (defined getgrnam("root")) {
		$opt_wheel = "root";
	}
}

if (!$opt_users) {
	if (defined getgrnam("users")) {
		$opt_users = "users";
	}
}

$opt_nobody || die "Unable to determine a user for 'nobody'\n";
$opt_nogroup || die "Unable to determine a group for 'nogroup'\n";
$opt_users || die "Unable to determine a group for 'user'\n";
$opt_wheel || die "Unable to determine a group for 'wheel'\n";

print "Using nobody='$opt_nobody'  nogroup='$opt_nogroup'  wheel='$opt_wheel'  users='$opt_users'\n";

print "generating ldif ...\n";

$dnsdomain = lc($opt_realm);
$dnsname = lc($opt_hostname).".".$dnsdomain;
$basedn = "DC=" . join(",DC=", split(/\./, $opt_realm));

my $data = FileLoad("provision.ldif") || die "Unable to load provision.ldif\n";

$data .= add_foreign("S-1-5-7", "Anonymous", "\${NOBODY}");
$data .= add_foreign("S-1-1-0", "World", "\${NOGROUP}");
$data .= add_foreign("S-1-5-2", "Network", "\${NOGROUP}");
$data .= add_foreign("S-1-5-18", "System", "root");
$data .= add_foreign("S-1-5-11", "Authenticated Users", "\${USERS}");

if (!$opt_adminpass) {
	$opt_adminpass = randpass();
	print "chose random Administrator password '$opt_adminpass'\n";
}

# allow provisioning to be run from the source directory
$ENV{"PATH"} .= ":bin";


my $res = apply_substitutions($data);

my $newdb = "newdb." . int(rand(1000));

print "Putting new database files in $newdb\n";

mkdir($newdb) || die "Unable to create temporary directory $newdb\n";

FileSave("$newdb/sam.ldif", $res);

print "creating $newdb/sam.ldb ...\n";

system("ldbadd -H $newdb/sam.ldb $newdb/sam.ldif") == 0 || die "Failed to create sam.ldb\n";

$data = FileLoad("rootdse.ldif") || die "Unable to load rootdse.ldif\n";

$res = apply_substitutions($data);

FileSave("$newdb/rootdse.ldif", $res);

print "creating $newdb/rootdse.ldb ...\n";

system("ldbadd -H $newdb/rootdse.ldb $newdb/rootdse.ldif") == 0 || die "Failed to create rootdse.ldb\n";

$data = FileLoad("secrets.ldif") || die "Unable to load secrets.ldif\n";

$res = apply_substitutions($data);

FileSave("$newdb/secrets.ldif", $res);

print "creating $newdb/secrets.ldb ...\n";

system("ldbadd -H $newdb/secrets.ldb $newdb/secrets.ldif") == 0 || die "Failed to create secrets.ldb\n";

$data = FileLoad("provision.zone") || die "Unable to load provision.zone\n";

$res = apply_substitutions($data);

print "saving dns zone to $newdb/$dnsdomain.zone ...\n";

FileSave("$newdb/$dnsdomain.zone", $res);

print "creating $newdb/hklm.ldb ... \n";

system("ldbadd -H $newdb/hklm.ldb hklm.ldif") == 0 || die "Failed to create hklm.ldb\n";

print "

Installation:
- Please move $newdb/*.ldb to the private/ directory of your
  Samba4 installation
- Please use $newdb/dnsdomain.zone in BIND on your dns server
";


