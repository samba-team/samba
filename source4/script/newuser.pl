#!/usr/bin/perl -w
# simple hack script to add a new user for Samba4


use strict;
use Socket;
use Getopt::Long;

my $opt_password;
my $opt_username;
my $opt_unixname;
my $opt_samdb = "/usr/local/samba/private/sam.ldb";


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

sub search($$)
{
	my $expr = shift;
	my $attrib = shift;
	my $res = `ldbsearch \"$expr\" $attrib | grep ^$attrib | cut -d' ' -f2- | head -1`;
	chomp $res;
	return $res;
}

############################################
# show some help
sub ShowHelp()
{
	print "
Samba4 newuser

provision.pl [options]
  --username  USERNAME     choose new username
  --password  PASSWORD     set password
  --samdb     DBPATH       path to sam.ldb

You must provide at least a username

";
	exit(1);
}

my $opt_help;

GetOptions(
	    'help|h|?' => \$opt_help, 
	    'username=s' => \$opt_username,
	    'unixname=s' => \$opt_unixname,
	    'password=s' => \$opt_password,
	    'samdb=s' => \$opt_samdb
	    );

if ($opt_help || !$opt_username) {
	ShowHelp();
}

if (!$opt_password) {
	$opt_password = randpass();
	print "chose random password '$opt_password'\n";
}

if (!$opt_unixname) {
	$opt_unixname = $opt_username;
}

my $res = "";

# allow provisioning to be run from the source directory
$ENV{"PATH"} .= ":bin";

$ENV{"LDB_URL"} = $opt_samdb;

my $domain_sid = search("(objectClass=domainDNS)", "objectSid");
my $domain_dn = search("(objectClass=domainDNS)", "dn");

my $ldif = `ldbsearch 'cn=TemplateUser' | grep -v Template | grep -v '^#'`;
chomp $ldif;

my $sid;

# crude way of working out a rid
for (my $i=1001;$i<1100;$i++) {
	if (search("objectSid=$domain_sid-$i","objectSid") eq "") {
		$sid = "$domain_sid-$i";
		last;
	}
}

print "Chose new SID $sid\n";

my $dom_users = search("name=Domain Users", "dn");


$ldif .= "sAMAccountName: $opt_username\n";
$ldif .= "name: $opt_username\n";
$ldif .= "objectSid: $sid\n";
$ldif .= "objectGUID: " . randguid() . "\n";
$ldif .= "memberOf: $dom_users\n";
$ldif .= "userAccountControl: 0x10200\n";
$ldif .= "sAMAccountType: 0x30000000\n";
$ldif .= "objectClass: user\n";
$ldif .= "unicodePwd: $opt_password\n";
$ldif .= "unixName: $opt_unixname\n";

my $user_dn = "CN=$opt_username,CN=Users,$domain_dn";

open FILE, ">newuser.ldif";
print FILE "dn: $user_dn";
print FILE "$ldif\n";
close FILE;

open FILE, ">modgroup.ldif";
print FILE "
dn: CN=Domain Users,CN=Users,$domain_dn
changetype: modify
add: member
member: $user_dn
";
close FILE;

system("ldbadd newuser.ldif");
system("ldbmodify modgroup.ldif");
