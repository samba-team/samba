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
use dot;
use strict;

sub smb_build_main($)
{
	my $INPUT = shift;
	my %SMB_BUILD_CTX = (
		INPUT => $INPUT
	);

	my @mkfiles = (
		"gtk/config.mk", 
		"smbd/config.mk",
		"smbd/process_model.mk",
		"libnet/config.mk",
		"auth/config.mk",
		"nsswitch/config.mk",
		"lib/basic.mk",
		"lib/dcom/config.mk",
		"lib/socket/config.mk",
		"lib/ldb/config.mk",
		"lib/tdb/config.mk",
		"lib/registry/config.mk",
		"lib/messaging/config.mk",
		"smb_server/config.mk",
		"rpc_server/config.mk",
		"ldap_server/config.mk",
		"libcli/auth/gensec.mk",
		"libcli/auth/config.mk",
		"libcli/ldap/config.mk",
		"libcli/config.mk",
		"utils/net/config.mk",
		"utils/config.mk",
		"ntvfs/posix/config.mk",
		"ntvfs/config.mk",
		"ntvfs/unixuid/config.mk",
		"torture/config.mk",
		"librpc/config.mk",
		"client/config.mk",
		"libcli/libsmb.mk");

	$| = 1;

	for my $mkfile (@mkfiles) {
		config_mk::import_file($SMB_BUILD_CTX{INPUT}, $mkfile);
	}

	%{$SMB_BUILD_CTX{DEPEND}} = input::check(\%SMB_BUILD_CTX);
	
	%{$SMB_BUILD_CTX{OUTPUT}} = output::create_output($SMB_BUILD_CTX{DEPEND});

	makefile::create_makefile_in($SMB_BUILD_CTX{OUTPUT});

	smb_build_h::create_smb_build_h($SMB_BUILD_CTX{OUTPUT});

	open DOTTY, ">samba4-deps.dot";
	print DOTTY dot::generate($SMB_BUILD_CTX{DEPEND});
	close DOTTY;
}
1;
