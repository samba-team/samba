###########################################################
### SMB Build System					###
### - the main program					###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################

use smb_build::makefile;
use smb_build::smb_build_h;
use smb_build::input;
use smb_build::config_mk;
use smb_build::output;
use smb_build::dot;
use strict;

my $config_list = "config.list";

sub smb_build_main($$)
{
	my $INPUT = shift;
	my $settings = shift;

	my @mkfiles = split('\n', `grep -v ^# $config_list`);

	$| = 1;

	for my $mkfile (@mkfiles) {
		config_mk::import_file($INPUT, $mkfile);
	}

	my $DEPEND = input::check($INPUT);
	
	my $OUTPUT = output::create_output($DEPEND);

	makefile::create_makefile_in($OUTPUT, $settings, "Makefile.in");

	smb_build_h::create_smb_build_h($OUTPUT, "include/smb_build.h");

	open DOTTY, ">samba4-deps.dot";
	print DOTTY dot::generate($DEPEND);
	close DOTTY;
}

1;
