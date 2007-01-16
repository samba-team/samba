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
use smb_build::summary;
use smb_build::config;
use strict;

my $INPUT = {};
my $mkfile = smb_build::config_mk::run_config_mk($INPUT, $config::config{srcdir}, $config::config{builddir}, "main.mk");

my $subsys_output_type;
$subsys_output_type = ["STATIC_LIBRARY"];

my $library_output_type;
if ($config::config{USESHARED} eq "true") {
	$library_output_type = ["SHARED_LIBRARY", "STATIC_LIBRARY"];
} else {
	$library_output_type = ["STATIC_LIBRARY"];
	push (@$library_output_type, "SHARED_LIBRARY") if 
						($config::config{BLDSHARED} eq "true")
}

my $module_output_type;
if ($config::config{USESHARED} eq "true") {
	$module_output_type = ["SHARED_LIBRARY"];
} else {
	$module_output_type = ["INTEGRATED"];
}

my $DEPEND = smb_build::input::check($INPUT, \%config::enabled,
				     $subsys_output_type,
				     $library_output_type,
				     $module_output_type);
my $OUTPUT = output::create_output($DEPEND, \%config::config);
$config::config{SUBSYSTEM_OUTPUT_TYPE} = $subsys_output_type;
$config::config{LIBRARY_OUTPUT_TYPE} = $library_output_type;
$config::config{MODULE_OUTPUT_TYPE} = $module_output_type;
my $mkenv = new smb_build::makefile(\%config::config, $mkfile);

foreach my $key (values %$OUTPUT) {
	next unless defined $key->{OUTPUT_TYPE};

	$mkenv->Integrated($key) if grep(/INTEGRATED/, @{$key->{OUTPUT_TYPE}});
}

foreach my $key (values %$OUTPUT) {
	next unless defined $key->{OUTPUT_TYPE};

	$mkenv->StaticLibrary($key) if grep(/STATIC_LIBRARY/, @{$key->{OUTPUT_TYPE}});
	$mkenv->PkgConfig($key, $OUTPUT) if $key->{TYPE} eq "LIBRARY" 
		                    and defined($key->{VERSION});
	$mkenv->SharedLibrary($key) if grep(/SHARED_LIBRARY/, @{$key->{OUTPUT_TYPE}});
	$mkenv->Binary($key) if grep(/BINARY/, @{$key->{OUTPUT_TYPE}});
	$mkenv->Manpage($key) if defined($key->{MANPAGE});
	$mkenv->Header($key) if defined($key->{PUBLIC_HEADERS});
	$mkenv->ProtoHeader($key) if defined($key->{PRIVATE_PROTO_HEADER}) or 
								 defined($key->{PUBLIC_PROTO_HEADER});
}

$mkenv->write("Makefile");
header::create_smb_build_h($OUTPUT, "include/build.h");

cflags::create_cflags($OUTPUT, "extra_cflags.txt");

summary::show($OUTPUT, \%config::config);

1;
