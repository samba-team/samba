###########################################################
### SMB Build System					###
### - the dump & debug functions 			###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################

package dump;
use strict;

use Data::Dumper;

sub dump_ctx($)
{
	my $ctx = shift;

	open (DUMP,"> config.smb_build.dump");
	
	print DUMP Dumper($ctx);

	close(DUMP);
}

1;
