#!/usr/bin/perl
##
## Example script of how you could import and smbpasswd file into an LDAP
## directory using the Mozilla PerLDAP module.
##
## writen by jerry@samba.org
##

use Mozilla::LDAP::Conn;
use Mozilla::LDAP::Entry;

#################################################
## set these to a value appropriate for your site
##

$DN="ou=people,dc=plainjoe,dc=org";
$ROOTDN="cn=Manager,dc=plainjoe,dc=org";
$rootpw = "secret";
$LDAPSERVER="localhost";

##
## end local site variables
#################################################

$conn = new Mozilla::LDAP::Conn ("$LDAPSERVER", "389", $ROOTDN, $rootpw );
die "Unable to connect to LDAP server $LDAPSERVER" unless $conn;


while ( $string = <STDIN> ) {
	chop ($string);

	## get the account information
	@smbentry = split (/:/, $string);

	## check for the existence of the posixAccount first

	## FIXME!!  Should do a getownam() and let the NSS modules lookup the account
	## This way you can have a UNIX account in /etc/passwd and the smbpasswd i
	## entry in LDAP.
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
}

$conn->close();
exit 0;
