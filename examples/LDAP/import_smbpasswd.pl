#!/usr/bin/perl
##
## Example script og how you could import and smbpasswd file into an LDAP
## directory using the Mozilla PerLDAP module.
##
## wrriten by jerry@samba.org
##

use Mozilla::LDAP::Conn;
use Mozilla::LDAP::Entry;

$DN="ou=people,dc=plainjoe,dc=org";
$ROOTDN="cn=Manager,dc=plainjoe,dc=org";
$rootpw = "secret";
$LDAPSERVER="localhost";


print "Connecting to $LDAPSERVER...";
$conn = new Mozilla::LDAP::Conn ("$LDAPSERVER", "389", $ROOTDN, $rootpw );
die "Unable to connect to LDAP server $LDAPSERVER" unless $conn;
print "connected!\n";

if ("$ARGV[0]") {
	open (SMBPASSFILE, "$ARGV[0]") || die $!;
	$infile = SMBPASSFILE;
}
else {
	$infile = STDIN;
}

while ( $string = <$infile> ) {
	chop ($string);

	## get the account information
	@smbentry = split (/:/, $string);

	## scheck for the existence of the posixAccount first
	$result = $conn->search ("$DN", "sub", "(&(uid=$smbentry[0])(objectclass=posixAccount))");
	if ( ! $result ) {
		print STDERR "uid=$smbentry[0] does not have a posixAccount entry in the directory!\n";
		next;
	}

	print "Updating [" . $result->getDN() . "]\n";

	## Do we need to add the 'objectclass: smbPasswordEntry' attribute?
	if (! $result->hasValue("objectclass", "smbPasswordEntry")) {
		$result->addValue("objectclass", "smbPasswordEntry");
	}
	
	## Set other attribute values
	$result->setValues ("lmPassword", $smbentry[2]);
	$result->setValues ("ntPassword", $smbentry[3]);
	$result->setValues ("acctFlags",  $smbentry[4]);
	$result->setValues ("pwdLastSet", substr($smbentry[5],4));

	if (! $conn->update($result)) {
		print "Error updating!\n";
	}

	## $result->printLDIF();
}

close ($infile);
$conn->close();
exit 0;
