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
use strict;

sub smb_build_main($)
{
	my $SMB_BUILD_CTX = shift;
	check_input($SMB_BUILD_CTX);

	create_depend($SMB_BUILD_CTX);

	create_output($SMB_BUILD_CTX);

	create_makefile_in($SMB_BUILD_CTX);

	create_smb_build_h($SMB_BUILD_CTX);

	return 0;
}
1;
