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
use config;
use strict;

my $INPUT = {};

config_mk::import_files($INPUT, "config.list");
my $DEPEND = smb_build::input::check($INPUT, \%config::enabled);
my $OUTPUT = output::create_output($DEPEND);
makefile::create_makefile_in($OUTPUT, "Makefile.in");
smb_build_h::create_smb_build_h($OUTPUT, "include/smb_build.h");

open DOTTY, ">samba4-deps.dot";
print DOTTY dot::generate($DEPEND);
close DOTTY;

1;
