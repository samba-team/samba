###########################################################
### SMB Build System					###
### - the main program					###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################

use makefile;
use depend;
use smb_build_h;
use input;
use config_mk;
use output;
use dump;
use strict;

sub smb_build_main($)
{
	my $SMB_BUILD_CTX = shift;
	input::check($SMB_BUILD_CTX);

	depend::create_depend($SMB_BUILD_CTX);

	output::create_output($SMB_BUILD_CTX);

	makefile::create_makefile_in($SMB_BUILD_CTX);

	smb_build_h::create_smb_build_h($SMB_BUILD_CTX);

	dump::dump_ctx($SMB_BUILD_CTX);

	return 0;
}
1;
