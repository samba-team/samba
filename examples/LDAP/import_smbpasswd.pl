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

$DN="ou=people,dc=plainjoe,dc=org";
$ROOTDN="cn=Manager,dc=plainjoe,dc=org";
# If you use perl special character  in your
# rootpw, escape them:
# $rootpw = "secr\@t" instead of $rootpw = "secr@t"
$rootpw = "n0pass";
$LDAPSERVER="scooby";

##
## end local site variables
#################################################

$ldap = Net::LDAP->new($LDAPSERVER) or die "Unable to connect to LDAP server $LDAPSERVER";

## Bind as $ROOTDN so you can do updates
$mesg = $ldap->bind($ROOTDN, password => $rootpw);
$mesg->error() if $mesg->code();

while ( $string = <STDIN> ) {
	chomp ($string);

	## Get the account info from the smbpasswd file
	@smbentry = split (/:/, $string);

	## Check for the existence of a system account
	@getpwinfo = getpwnam($smbentry[0]);
	if (! @getpwinfo ) {
	    print STDERR "**$smbentry[0] does not have a system account... \n";
	    next;
        }
	## Calculate RID = uid*2 +1000
	$rid=@getpwinfo[2]*2+1000;
	
	## check and see if account info already exists in LDAP.
        $result = $ldap->search ( base => "$DN",
				  scope => "sub",
				  filter => "(uid=$smbentry[0])"
				);

        ## If no LDAP entry exists, create one.
	if ( $result->count == 0 ) {
		$new_entry  = Net::LDAP::Entry->new();
		$new_entry->add( dn => "uid=$smbentry[0],$DN",
				 uid => $smbentry[0],
                                 rid => $rid,
				 lmPassword => $smbentry[2],
				 ntPassword => $smbentry[3],
                                 acctFlags => $smbentry[4],
				 cn => $smbentry[0],
                                 pwdLastSet => hex(substr($smbentry[5],4)),
                                 objectclass => 'sambaAccount' );

		$result = $ldap->add( $new_entry );
		$result->error() if $result->code();
		print "Adding [uid=" . $smbentry[0] . "," . $DN . "]\n";

        ## Otherwise, supplement/update the existing entry.
	} 
	elsif ($result->count == 1) 
	{
		# Put the search results into an entry object
		$entry = $result->entry(0);

		print "Updating [" . $entry->dn . "]\n";

		## Add the objectclass: sambaAccount attribute if it's not there
		@values = $entry->get_value( "objectclass" );
		$flag = 1;
		foreach $item (@values) {
			print "$item\n";
			if ( "$item" eq "sambaAccount" ) {
				$flag = 0;
			}
		}
		if ( $flag ) {
	    		## Adding sambaAccount objectclass requires adding at least rid:
			## uid attribute already exists we know since we searched on it
			$entry->add(objectclass => "sambaAccount",
       				   rid	       => $rid );
	    }

	    ## Set the other attribute values
	    $entry->replace(rid        => $rid,
			    lmPassword => $smbentry[2],
			    ntPassword => $smbentry[3],
			    acctFlags  => $smbentry[4],
			    pwdLastSet => hex(substr($smbentry[5],4)));

	    ## Apply changes to the LDAP server
            $updatemesg = $entry->update($ldap);
	    $updatemesg->error() if $updatemesg->code();

        ## If we get here, the LDAP search returned more than one value
        ## which shouldn't happen under normal circumstances.
	} else {
	    print STDERR "LDAP search returned more than one entry for $smbentry[0]... skipping!\n";
	    next;
        }
}

$ldap->unbind();
exit 0;


