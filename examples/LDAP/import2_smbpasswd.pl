#!/usr/bin/perl
##
## Example script of how you could import and smbpasswd file into an LDAP
## directory using the Mozilla PerLDAP module.
##
## written by jerry@samba.org
##
## ported to Net::LDAP by dkrovich@slackworks.com

use Net::LDAP;

#################################################
## set these to a value appropriate for your site
##

$DN="dc=samba,dc=my-domain,dc=com";
$ROOTDN="cn=Manager,dc=my-domain,dc=com";
$rootpw = "secret";
$LDAPSERVER="localhost";

##
## end local site variables
#################################################

$ldap = Net::LDAP->new($LDAPSERVER) or die "Unable to connect to LDAP server $LDAPSERVER";

## Bind as $ROOTDN so you can do updates
$mesg = $ldap->bind($ROOTDN, password => $rootpw);

while ( $string = <STDIN> ) {
	chop ($string);

	## get the account information
	@smbentry = split (/:/, $string);

	## check for the existence of the posixAccount first

	## FIXME!!  Should do a getownam() and let the NSS modules lookup the account
	## This way you can have a UNIX account in /etc/passwd and the smbpasswd i
	## entry in LDAP.
        $result = $ldap->search ( base => "$DN",
				  scope => "sub",
				  filter  =>"(&(uid=$smbentry[0])(objectclass=posixAccount))"
				);

	if ( $result->count != 1 ) {
		print STDERR "uid=$smbentry[0] does not have a posixAccount entry in the directory!\n";
		next;
	}

	# Put the results into an entry object
	$entry = $result->shift_entry;

	print "Updating [" . $entry->dn . "]\n";

	## Add the objectclass: smbPasswordEntry attribute.
        ## If the attribute is already there nothing bad happens.
        $entry->add(objectclass => "smbPasswordEntry");

	## Set other attribute values
	$entry->replace(lmPassword => $smbentry[2]);
        $entry->replace(ntPassword => $smbentry[3]);
        $entry->replace(acctFlags => $smbentry[4]);
        $entry->replace(pwdLastSet => substr($smbentry[5],4));

        ## Update the LDAP server
	if (! $entry->update($ldap) ) {
		print "Error updating!\n";
	}
}

$ldap->unbind();
exit 0;

