###########################################################
### SMB Build System					###
### - the dump & debug functions 			###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################

use Data::Dumper;
sub _dump_ctx($)
{
	my $ctx = shift;

	open (DUMP,"> config.smb_build.dump");
	
	print DUMP Dumper($ctx);

	close(DUMP);

	return;
}

_dump_ctx($SMB_BUILD_CTX);
