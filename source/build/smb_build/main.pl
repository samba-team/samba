###########################################################
### SMB Build System					###
### - the main program					###
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

sub smb_build_main($)
{
	check_input($SMB_BUILD_CTX);

	create_depend($SMB_BUILD_CTX);

	create_output($SMB_BUILD_CTX);

	create_makefile_in($SMB_BUILD_CTX);

	create_smb_build_h($SMB_BUILD_CTX);

	_dump_ctx($SMB_BUILD_CTX);

	return 0;
}