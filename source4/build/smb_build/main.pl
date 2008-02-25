# Samba Build System					
# - the main program					
#							
#  Copyright (C) Stefan (metze) Metzmacher 2004	
#  Copyright (C) Jelmer Vernooij 2005
#  Released under the GNU GPL				

use smb_build::makefile;
use smb_build::input;
use smb_build::config_mk;
use smb_build::output;
use smb_build::env;
use smb_build::summary;
use smb_build::config;
use strict;

my $INPUT = {};
my $mkfile = smb_build::config_mk::run_config_mk($INPUT, $config::config{srcdir}, $config::config{builddir}, "main.mk");

my $subsys_output_type = ["MERGED_OBJ"];

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
	$module_output_type = ["MERGED_OBJ"];
}

my $DEPEND = smb_build::input::check($INPUT, \%config::enabled,
				     $subsys_output_type,
				     $library_output_type,
				     $module_output_type);
my $OUTPUT = output::create_output($DEPEND, \%config::config);
my $mkenv = new smb_build::makefile(\%config::config, $mkfile);

my $shared_libs_used = 0;
foreach my $key (values %$OUTPUT) {
	$mkenv->_prepare_list($key, "OBJ_LIST");
	push(@{$mkenv->{all_objs}}, "\$($key->{NAME}_OBJ_LIST)");
}

foreach my $key (values %$OUTPUT) {
	next unless defined $key->{OUTPUT_TYPE};

	$mkenv->StaticLibraryPrimitives($key) if grep(/STATIC_LIBRARY/, @{$key->{OUTPUT_TYPE}});
	$mkenv->MergedObj($key) if grep(/MERGED_OBJ/, @{$key->{OUTPUT_TYPE}});
	if (defined($key->{PC_FILE})) {
		$mkenv->output("PC_FILES += $key->{BASEDIR}/$key->{PC_FILE}\n");
	} 
	$mkenv->SharedLibraryPrimitives($key) if ($key->{TYPE} eq "LIBRARY") and
					grep(/SHARED_LIBRARY/, @{$key->{OUTPUT_TYPE}});
	if ($key->{TYPE} eq "LIBRARY" and 
	    ${$key->{OUTPUT_TYPE}}[0] eq "SHARED_LIBRARY") {
		$shared_libs_used = 1;
	}
	$mkenv->SharedModulePrimitives($key) if ($key->{TYPE} eq "MODULE" or 
								   $key->{TYPE} eq "PYTHON") and
					grep(/SHARED_LIBRARY/, @{$key->{OUTPUT_TYPE}});
	$mkenv->PythonFiles($key) if defined($key->{PYTHON_FILES});
	$mkenv->Manpage($key) if defined($key->{MANPAGE});
	$mkenv->Header($key) if defined($key->{PUBLIC_HEADERS});
	if ($key->{TYPE} eq "MODULE" and defined($key->{INIT_FUNCTION})) {
		$mkenv->output("$key->{SUBSYSTEM}_INIT_FUNCTIONS += \"$key->{INIT_FUNCTION},\"\n");
	}
	$mkenv->CFlags($key);
}

foreach my $key (values %$OUTPUT) {
	next unless defined $key->{OUTPUT_TYPE};

	$mkenv->Integrated($key) if grep(/INTEGRATED/, @{$key->{OUTPUT_TYPE}});
}

foreach my $key (values %$OUTPUT) {
	next unless defined $key->{OUTPUT_TYPE};

	$mkenv->StaticLibrary($key) if grep(/STATIC_LIBRARY/, @{$key->{OUTPUT_TYPE}});
	$mkenv->SharedLibrary($key) if ($key->{TYPE} eq "LIBRARY") and
					grep(/SHARED_LIBRARY/, @{$key->{OUTPUT_TYPE}});
	$mkenv->SharedModule($key) if ($key->{TYPE} eq "MODULE" or 
								   $key->{TYPE} eq "PYTHON") and
					grep(/SHARED_LIBRARY/, @{$key->{OUTPUT_TYPE}});
	$mkenv->Binary($key) if grep(/BINARY/, @{$key->{OUTPUT_TYPE}});
	$mkenv->ProtoHeader($key) if defined($key->{PRIVATE_PROTO_HEADER}) or 
					 defined($key->{PUBLIC_PROTO_HEADER});
	$mkenv->InitFunctions($key) if defined($key->{INIT_FUNCTIONS});
}

$mkenv->write("data.mk");

summary::show($OUTPUT, \%config::config);

1;
