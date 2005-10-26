###########################################################
### SMB Build System					###
### - the main program					###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Copyright (C) Jelmer Vernooij 2005
###  Released under the GNU GPL				###
###########################################################

use smb_build::makefile;
use smb_build::smb_build_h;
use smb_build::input;
use smb_build::config_mk;
use smb_build::output;
use smb_build::dot;
use smb_build::env;
use config;
use strict;

my $INPUT = {};

my $mkfile = smb_build::config_mk::run_config_mk($INPUT, "main.mk");

if (defined($ENV{"SUBSYSTEM_OUTPUT_TYPE"})) {
	$smb_build::input::subsystem_output_type = $ENV{SUBSYSTEM_OUTPUT_TYPE};
} elsif ($config::config{BLDMERGED} eq "true") {
	$smb_build::input::subsystem_output_type = "MERGEDOBJ";
}

if (defined($ENV{"LIBRARY_OUTPUT_TYPE"})) {
	$smb_build::input::subsystem_output_type = $ENV{LIBRARY_OUTPUT_TYPE};
} elsif ($config::config{BLDSHARED} eq "true") {
	# FIXME: This should really be SHARED_LIBRARY
	$smb_build::input::subsystem_output_type = "MERGEDOBJ";
} elsif ($config::config{BLDMERGED} eq "true") {
	$smb_build::input::subsystem_output_type = "MERGEDOBJ";
}

my $DEPEND = smb_build::input::check($INPUT, \%config::enabled);
my $OUTPUT = output::create_output($DEPEND);
my $mkenv = new smb_build::makefile(\%config::config, $OUTPUT, $mkfile);
$mkenv->write("Makefile");
smb_build_h::create_smb_build_h($OUTPUT, "include/smb_build.h");

open DOTTY, ">samba4-deps.dot";
print DOTTY dot::generate($DEPEND);
close DOTTY;

1;
