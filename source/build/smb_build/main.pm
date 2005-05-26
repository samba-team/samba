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
use dot;
use strict;

sub smb_build_main($)
{
	my $INPUT = shift;

	my @mkfiles = (
		"dsdb/config.mk",
		"gtk/config.mk",
		"smbd/config.mk",
		"smbd/process_model.mk",
		"libnet/config.mk",
		"auth/config.mk",
		"nsswitch/config.mk",
		"lib/basic.mk",
		"lib/socket/config.mk",
		"lib/ldb/config.mk",
		"lib/talloc/config.mk",
		"lib/tdb/config.mk",
		"lib/registry/config.mk",
		"lib/messaging/config.mk",
		"lib/events/config.mk",
		"lib/popt/config.mk",
		"lib/cmdline/config.mk",
		"lib/socket_wrapper/config.mk",
		"param/config.mk",
		"smb_server/config.mk",
		"rpc_server/config.mk",
		"ldap_server/config.mk",
		"web_server/config.mk",
		"winbind/config.mk",
		"nbt_server/config.mk",
		"cldap_server/config.mk",
		"auth/gensec/config.mk",
		"auth/kerberos/config.mk",
		"auth/ntlmssp/config.mk",
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
		"libcli/libsmb.mk",
		"libcli/config.mk",
		"libcli/security/config.mk",
		"lib/com/config.mk",
		"scripting/swig/config.mk",
	);

	$| = 1;

	for my $mkfile (@mkfiles) {
		config_mk::import_file($INPUT, $mkfile);
	}

	my $DEPEND = input::check($INPUT);
	
	my $OUTPUT = output::create_output($DEPEND);

	makefile::create_makefile_in($OUTPUT, "Makefile.in");

	smb_build_h::create_smb_build_h($OUTPUT, "include/smb_build.h");

	open DOTTY, ">samba4-deps.dot";
	print DOTTY dot::generate($DEPEND);
	close DOTTY;
}

1;
