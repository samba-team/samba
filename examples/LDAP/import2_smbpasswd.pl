#!/usr/bin/perl
##
## Example script of how you could import a smbpasswd file into an LDAP
## directory using the Mozilla PerLDAP module.
##
## writen by jerry@samba.org
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

	## Get the account info from the smbpasswd file
	@smbentry = split (/:/, $string);

	## Check for the existence of a system account
	@getpwinfo = getpwnam($smbentry[0]);
	if (! @getpwinfo ) {
	    print STDERR "$smbentry[0] does not have a system account...  skipping\n";
	    next;
        }

	## check and see if account info already exists in LDAP.
        $result = $ldap->search ( base => "$DN",
				  scope => "sub",
				  filter => "(&(|(objectclass=posixAccount)(objectclass=smbPasswordEntry))(uid=$smbentry[0]))"
				);

        ## If no LDAP entry exists, create one.
	if ( $result->count == 0 ) {
           $entry = $ldap->add ( dn => "uid=$smbentry[0]\,$DN",
				 attrs => [
				    uid => $smbentry[0],
                                    uidNumber => @getpwinfo[2],
				    lmPassword => $smbentry[2],
				    ntPassword => $smbentry[3],
                                    acctFlags => $smbentry[4],
                                    pwdLastSet => substr($smbentry[5],4),
                                    objectclass => [ 'top', 'smbPasswordEntry' ]
                                  ]
				 );
	   print "Adding [uid=" . $smbentry[0] . "," . $DN . "]\n";

        ## Otherwise, supplement/update the existing entry.
	} elsif ($result->count == 1) {
	    # Put the search results into an entry object
	    $entry = $result->shift_entry;

	    print "Updating [" . $entry->dn . "]\n";

  	    ## Add the objectclass: smbPasswordEntry attribute if it's not there
	    @values = $entry->get_value( "objectclass" );
	    $flag = 1;
	    foreach $item (@values) {
	       if ( lc($item) eq "smbpasswordentry" ) {
		   print $item . "\n";
		   $flag = 0;
	       }
	    }
	    if ( $flag ) {
	       $entry->add(objectclass => "smbPasswordEntry");
	    }

	    ## Set the other attribute values
	    $entry->replace(lmPassword => $smbentry[2],
			    ntPassword => $smbentry[3],
			    acctFlags  => $smbentry[4],
			    pwdLastSet => substr($smbentry[5],4)
			    );

	    ## Apply changes to the LDAP server
            $updatemesg = $entry->update($ldap);
	    if ( $updatemesg->code )  {
		print "Error updating $smbentry[0]!\n";
	    }

        ## If we get here, the LDAP search returned more than one value
        ## which shouldn't happen under normal circumstances.
	} else {
	    print STDERR "LDAP search returned more than one entry for $smbentry[0]... skipping!\n";
	    next;
        }
}

$ldap->unbind();
exit 0;


