###########################################################
### SMB Build System					###
### - the main program					###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################

use makefile;
use smb_build_h;
use input;
use config_mk;
use output;
use direct;
use strict;

sub smb_build_main($)
{
	my $INPUT = shift;
	my %SMB_BUILD_CTX = (
		INPUT => $INPUT
	);

	%{$SMB_BUILD_CTX{DEPEND}} = input::check(\%SMB_BUILD_CTX);
	
	%{$SMB_BUILD_CTX{OUTPUT}} = output::create_output($SMB_BUILD_CTX{DEPEND});

	makefile::create_makefile_in($SMB_BUILD_CTX{OUTPUT});

	smb_build_h::create_smb_build_h($SMB_BUILD_CTX{OUTPUT});
}
1;
