#!/usr/bin/perl -w

# LDAP to unix password sync script for samba-tng
# originally by Jody Haynes <Jody.Haynes@isunnetworks.com>
# 12/12/2000    milos@interactivesi.com
#               modified for use with MD5 passwords
# 12/16/2000	mami@arena.sci.univr.it
#		modified to change lmpassword and ntpassword for samba
# 05/01/2001	mami@arena.sci.univr.it
#		modified for being also a /bin/passwd replacement
#
# ACHTUNG!!	For servers that support the LDAP Modify password 
#		extended op (e.g. OpenLDAP), see the "ldap password 
#		sync" option in smb.conf(5).  
#

$basedn = "ou=Students,dc=univr, dc=it";
$binddn = "uid=root,dc=univr,dc=it";
$scope = "sub";
$passwd = "mysecret";

foreach $arg (@ARGV) {
	if ($< != 0) {
		die "Only root can specify parameters\n";
	} else {
		if ( ($arg eq '-?') || ($arg eq '--help') ) {
			print "Usage: $0 [-o] [username]\n";
			print "  -o, --without-old-password	do not ask for old password (root only)\n";
			print "  -?, --help			show this help message\n";
			exit (-1);
		} elsif ( ($arg eq '-o') || ($arg eq '--without-old-password') ) {
			$oldpass = 1;
		} elsif (substr($arg,0) ne '-')  {
			$user = $arg;
			if (!defined(getpwnam($user))) {
				die "$0: Unknown user name '$user'\n";	;
			}
		}
	}
}

if (!defined($user)) {
	$user=$ENV{"USER"};
}

if (!defined($oldpass)) {
	system "stty -echo";
	print "Old password for user $user: ";
	chomp($oldpass=<STDIN>);
	print "\n";
	system "stty echo";

	$ntpwd = `/usr/local/sbin/smbencrypt '$oldpass'`;
	$lmpassword = substr($ntpwd, 0, index($ntpwd, ':')); chomp $lmpassword;
	$ntpassword = substr($ntpwd, index($ntpwd, ':')+1); chomp $ntpassword;

	# Find dn for user $user (maybe check unix password too?)
	$dn=`ldapsearch -b '$basedn' -s '$scope' '(&(uid=$user)(lmpassword=$lmpassword)(ntpassword=$ntpassword))'|head -1`;
	chomp $dn;

	if ($dn eq '') {
		print "Wrong password for user $user!\n";
		exit (-1);
	}
} else {
	# Find dn for user $user
	$dn=`ldapsearch -b '$basedn' -s '$scope' '(uid=$user)'|head -1`;
	chomp $dn;
}

system "stty -echo";
print "New password for user $user: ";
chomp($pass=<STDIN>);
print "\n";
system "stty echo";

system "stty -echo";
print "Retype new password for user $user: ";
chomp($pass2=<STDIN>);
print "\n";
system "stty echo";

if ($pass ne $pass2) {
	die "Wrong password!\n";
} else {
# MD5 password
$random = join '', ('.', '/', 0..9, 'A'..'Z', 'a'..'z')[rand 64, rand 64, rand 64, rand 64, rand 64, rand 64, rand 64, rand 64];
$bsalt = "\$1\$"; $esalt = "\$";
$modsalt = $bsalt.$random.$esalt;
$password = crypt($pass, $modsalt);

# LanManager and NT clear text passwords
$ntpwd = `/usr/local/sbin/smbencrypt '$pass'`;
chomp($lmpassword = substr($ntpwd, 0, index($ntpwd, ':')));
chomp($ntpassword = substr($ntpwd, index($ntpwd, ':')+1));

$FILE="|/usr/bin/ldapmodify -D '$binddn' -w $passwd";

open FILE or die;

print FILE <<EOF;
dn: $dn
changetype: modify
replace: userPassword
userPassword: {crypt}$password
-
changetype: modify
replace: lmpassword
lmpassword: $lmpassword
-
changetype: modify
replace: ntpassword
ntpassword: $ntpassword
-

EOF
close FILE;

}

exit 0;

