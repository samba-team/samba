# Samba Build System
# - the input checking functions
#
#  Copyright (C) Stefan (metze) Metzmacher 2004
#  Copyright (C) Jelmer Vernooij 2004
#  Released under the GNU GPL

use strict;
package smb_build::input;

use vars qw($library_output_type $subsystem_output_type $module_output_type);

$library_output_type = "OBJ_LIST";
$subsystem_output_type = "OBJ_LIST";
$module_output_type = "OBJ_LIST";
my $srcdir = ".";

sub strtrim($)
{
	$_ = shift;
	s/^[\t\n ]*//g;
	s/[\t\n ]*$//g;
	return $_;
}

sub str2array($)
{
	$_ = shift;
	s/^[\t\n ]*//g;
	s/[\t\n ]*$//g;
	s/([\t\n ]+)/ /g;

	return () if (length($_)==0);
	return split /[ \t\n]/;
}

sub check_subsystem($$)
{
	my ($INPUT, $subsys) = @_;
	if ($subsys->{ENABLE} ne "YES") {
		printf("Subsystem `%s' disabled\n",$subsys->{NAME});
		return;
	}
	
	unless(defined($subsys->{OUTPUT_TYPE})) {
		$subsys->{OUTPUT_TYPE} = $subsystem_output_type;
	}
}

sub check_module($$)
{
	my ($INPUT, $mod) = @_;

	die("Module $mod->{NAME} does not have a SUBSYSTEM set") if not defined($mod->{SUBSYSTEM});

	my $use_default = 0;

	if (!(defined($INPUT->{$mod->{SUBSYSTEM}}))) {
		$mod->{ENABLE} = "NO";
		return;
	}

	if ($mod->{ENABLE} ne "YES")
	{
		printf("Module `%s' disabled\n",$mod->{NAME});
		return;
	}

	if (defined($mod->{CHOSEN_BUILD}) and $mod->{CHOSEN_BUILD} ne "DEFAULT") 
	{
		$mod->{OUTPUT_TYPE} = $mod->{CHOSEN_BUILD};
	} else {
		$mod->{OUTPUT_TYPE} = $module_output_type;
	}

	if ($mod->{OUTPUT_TYPE} eq "SHARED_LIBRARY" or 
	    $mod->{OUTPUT_TYPE} eq "STATIC_LIBRARY") {
		$mod->{INSTALLDIR} = "LIBDIR/$mod->{SUBSYSTEM}";
		push (@{$mod->{REQUIRED_SUBSYSTEMS}}, $mod->{SUBSYSTEM});
	} else {
		push (@{$INPUT->{$mod->{SUBSYSTEM}}{REQUIRED_SUBSYSTEMS}}, $mod->{NAME});
	}
}

sub check_library($$)
{
	my ($INPUT, $lib) = @_;

	if ($lib->{ENABLE} ne "YES") {
		printf("Library `%s' disabled\n",$lib->{NAME});
		return;
	}


	$lib->{OUTPUT_TYPE} = $library_output_type;

	unless (defined($lib->{MAJOR_VERSION})) {
		print "$lib->{NAME}: Please specify MAJOR_VERSION\n";
		return;
	}

	$lib->{INSTALLDIR} = "LIBDIR";
}

sub check_binary($$)
{
	my ($INPUT, $bin) = @_;

	if ($bin->{ENABLE} ne "YES") {
		printf("Binary `%s' disabled\n",$bin->{NAME});
		return;
	}

	($bin->{BINARY} = (lc $bin->{NAME})) if not defined($bin->{BINARY});

	$bin->{OUTPUT_TYPE} = "BINARY";
}

sub calc_unique_deps($$)
{
	sub calc_unique_deps($$);
	my ($deps, $udeps) = @_;

	foreach my $dep (@{$deps}) {
		if (not defined($udeps->{$$dep->{NAME}})) {
      		   if (defined ($$dep->{OUTPUT_TYPE}) && (($$dep->{OUTPUT_TYPE} eq "OBJ_LIST")
			    or ($$dep->{OUTPUT_TYPE} eq "MERGEDOBJ"))) {
   			        $udeps->{$$dep->{NAME}} = "BUSY";
			        calc_unique_deps($$dep->{DEPENDENCIES}, $udeps);
		        }
			$udeps->{$$dep->{NAME}} = $$dep;
		}
	}
}

###########################################################
# This function checks the input from the configure script 
#
# check_input($INPUT)
#
# $INPUT -	the global INPUT context
# $enabled - list of enabled subsystems/libs
sub check($$)
{
	my ($INPUT, $enabled) = @_;

	foreach my $part (values %$INPUT) {
		if (defined($enabled->{$part->{NAME}})) { 
			$part->{ENABLE} = $enabled->{$part->{NAME}};
			next;
		}
		
		unless(defined($part->{ENABLE})) {
			$part->{ENABLE} = "YES";
		}
	}

	foreach my $k (keys %$INPUT) {
		my $part = $INPUT->{$k};

		check_subsystem($INPUT, $part) if ($part->{TYPE} eq "SUBSYSTEM");
		check_module($INPUT, $part) if ($part->{TYPE} eq "MODULE");
		check_library($INPUT, $part) if ($part->{TYPE} eq "LIBRARY");
		check_binary($INPUT, $part) if ($part->{TYPE} eq "BINARY");
	}

	my %depend = %$INPUT;

	foreach my $part (values %depend) {
		
		# Generate list of dependencies
		$part->{DEPENDENCIES} = [];

		foreach my $key (@{$part->{REQUIRED_SUBSYSTEMS}}) {
			die("$part->{NAME} has undefined dependency $key\n") if not defined($depend{$key});
			push (@{$part->{DEPENDENCIES}}, \$depend{$key});
		}

		delete ($part->{REQUIRED_SUBSYSTEMS});
	}

	foreach my $part (values %depend) {
		$part->{UNIQUE_DEPENDENCIES} = {};
		calc_unique_deps($part->{DEPENDENCIES}, $part->{UNIQUE_DEPENDENCIES});
	}

	return \%depend;
}

1;
