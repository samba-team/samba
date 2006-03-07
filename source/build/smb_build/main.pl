# Samba Build System					
# - the main program					
#							
#  Copyright (C) Stefan (metze) Metzmacher 2004	
#  Copyright (C) Jelmer Vernooij 2005
#  Released under the GNU GPL				

use smb_build::makefile;
use smb_build::header;
use smb_build::input;
use smb_build::config_mk;
use smb_build::output;
use smb_build::env;
use smb_build::cflags;
use config;
use strict;

my $INPUT = {};

my $mkfile = smb_build::config_mk::run_config_mk($INPUT, $config::config{srcdir}, "main.mk");

my $subsystem_output_type;

if (defined($ENV{"SUBSYSTEM_OUTPUT_TYPE"})) {
	$subsystem_output_type = $ENV{SUBSYSTEM_OUTPUT_TYPE};
} elsif ($config::config{BLDMERGED} eq "true") {
	$subsystem_output_type = "MERGEDOBJ";
} else {
	$subsystem_output_type = "OBJ_LIST";
}

my $library_output_type;
if (defined($ENV{"LIBRARY_OUTPUT_TYPE"})) {
	$library_output_type = $ENV{LIBRARY_OUTPUT_TYPE};
} elsif ($config::config{BLDSHARED} eq "true") {
	#FIXME: This should eventually become SHARED_LIBRARY 
	# rather then MERGEDOBJ once I'm certain it works ok -- jelmer
	$library_output_type = "MERGEDOBJ";
} elsif ($config::config{BLDMERGED} eq "true") {
	$library_output_type = "MERGEDOBJ";
} else {
	$library_output_type = "OBJ_LIST";
}

my $module_output_type;
if (defined($ENV{"MODULE_OUTPUT_TYPE"})) {
	$module_output_type = $ENV{MODULE_OUTPUT_TYPE};
} elsif ($config::config{BLDSHARED} eq "true") {
	#FIXME: This should eventually become SHARED_LIBRARY 
	# rather then MERGEDOBJ once I'm certain it works ok -- jelmer
	$module_output_type = "MERGEDOBJ";
} elsif ($config::config{BLDMERGED} eq "true") {
	$module_output_type = "MERGEDOBJ";
} else {
	$module_output_type = "OBJ_LIST";
}

my $DEPEND = smb_build::input::check($INPUT, \%config::enabled, 
	$subsystem_output_type, $library_output_type, $module_output_type);
my $OUTPUT = output::create_output($DEPEND, \%config::config);
$config::config{SUBSYSTEM_OUTPUT_TYPE} = $subsystem_output_type;
$config::config{LIBRARY_OUTPUT_TYPE} = $library_output_type;
$config::config{MODULE_OUTPUT_TYPE} = $module_output_type;
my $mkenv = new smb_build::makefile(\%config::config, $mkfile);

foreach my $key (values %$OUTPUT) {
	next unless defined $key->{OUTPUT_TYPE};

	$mkenv->MergedObj($key) if $key->{OUTPUT_TYPE} eq "MERGEDOBJ";
	$mkenv->ObjList($key) if $key->{OUTPUT_TYPE} eq "OBJLIST";
	$mkenv->StaticLibrary($key) if $key->{OUTPUT_TYPE} eq "STATIC_LIBRARY";
	$mkenv->PkgConfig($key) if ($key->{OUTPUT_TYPE} eq "SHARED_LIBRARY") and
						defined($key->{MAJOR_VERSION});
	$mkenv->SharedLibrary($key) if $key->{OUTPUT_TYPE} eq "SHARED_LIBRARY";
	$mkenv->Binary($key) if $key->{OUTPUT_TYPE} eq "BINARY";
	$mkenv->Manpage($key) if defined($key->{MANPAGE});
	$mkenv->Header($key) if defined($key->{PUBLIC_HEADERS});
	$mkenv->ProtoHeader($key) if defined($key->{PRIVATE_PROTO_HEADER});

#	$mkenv->DependencyInfo($key) if $config::config{developer} eq "yes";
}

$mkenv->write("Makefile");
header::create_smb_build_h($OUTPUT, "include/build.h");

cflags::create_cflags($OUTPUT, "extra_cflags.txt");

1;
