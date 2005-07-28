###########################################################
### SMB Build System					###
### - the input checking functions			###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Copyright (C) Jelmer Vernooij 2004	###
###  Released under the GNU GPL				###
###########################################################

use strict;
package smb_build::input;

my $subsystem_default_output_type = "OBJLIST";
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
		printf("Subsystem: %s disabled!\n",$subsys->{NAME});
		return;
	}
	
	unless(defined($subsys->{OUTPUT_TYPE})) {
		$subsys->{OUTPUT_TYPE} = $subsystem_default_output_type;
	}
}

sub check_module($$)
{
	my ($INPUT, $mod) = @_;

	die("Module $mod->{NAME} does not have a SUBSYSTEM set") if not defined($mod->{SUBSYSTEM});


	($mod->{DEFAULT_BUILD} = "STATIC") if not defined($mod->{DEFAULT_BUILD});
	
	my $use_default = 0;

	if (!(defined($INPUT->{$mod->{SUBSYSTEM}}))) {
		$mod->{BUILD} = "NOT";
		$mod->{ENABLE} = "NO";
		printf("Module: %s...PARENT SUBSYSTEM ($mod->{SUBSYSTEM}) DISABLED\n",$mod->{NAME});
		return;
	}

	if (($mod->{ENABLE} eq "STATIC") or 
	 	($mod->{ENABLE} eq "NOT") or 
		($mod->{ENABLE} eq "SHARED")) {
		$mod->{DEFAULT_BUILD} = $mod->{ENABLE};
	} elsif ($mod->{ENABLE} ne "YES")
	{
		$mod->{CHOSEN_BUILD} = "NOT";
	}

	if (not defined($mod->{CHOSEN_BUILD}) or $mod->{CHOSEN_BUILD} eq "DEFAULT") 
	{
		$mod->{CHOSEN_BUILD} = $mod->{DEFAULT_BUILD};
	}

	if ($mod->{CHOSEN_BUILD} eq "SHARED") {
		$mod->{ENABLE} = "YES";
		$mod->{OUTPUT_TYPE} = "SHARED_LIBRARY";
		push (@{$mod->{REQUIRED_SUBSYSTEMS}}, $mod->{SUBSYSTEM});
		printf("Module: %s...shared\n",$mod->{NAME});
	} elsif ($mod->{CHOSEN_BUILD} eq "STATIC") {
		$mod->{ENABLE} = "YES";
		push (@{$INPUT->{$mod->{SUBSYSTEM}}{REQUIRED_SUBSYSTEMS}}, $mod->{NAME});
		printf("Module: %s...static\n",$mod->{NAME});
		$mod->{OUTPUT_TYPE} = $subsystem_default_output_type;
	} else {
		$mod->{ENABLE} = "NO";
		printf("Module: %s...not\n",$mod->{NAME});
		return;
	}
}

sub check_library($$)
{
	my ($INPUT, $lib) = @_;

	if ($lib->{ENABLE} ne "YES") {
		printf("Library: %s...disabled\n",$lib->{NAME});
		return;
	}

	$lib->{OUTPUT_TYPE} = "SHARED_LIBRARY";
}

sub check_target($$)
{
	my ($INPUT, $bin) = @_;

	if (!defined($bin->{CMD})) {
		print "CMD not defined for target!\n";
	}

	$bin->{OUTPUT_TYPE} = "CUSTOM";
}

sub check_binary($$)
{
	my ($INPUT, $bin) = @_;

	if ($bin->{ENABLE} ne "YES") {
		printf("Binary: %s...disabled\n",$bin->{NAME});
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
			$udeps->{$$dep->{NAME}} = "BUSY";
			calc_unique_deps($$dep->{DEPENDENCIES}, $udeps);
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

	($subsystem_default_output_type = $ENV{SUBSYSTEM_OUTPUT_TYPE}) if (defined($ENV{"SUBSYSTEM_OUTPUT_TYPE"}));

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
		if (not defined($part->{TYPE})) {
			print STDERR "$k does not have a type set.. Perhaps it's only mentioned in a .m4 but not in a .mk file?\n";
			next;
		}
		check_subsystem($INPUT, $part) if ($part->{TYPE} eq "SUBSYSTEM");
		check_module($INPUT, $part) if ($part->{TYPE} eq "MODULE");
		check_library($INPUT, $part) if ($part->{TYPE} eq "LIBRARY");
		check_binary($INPUT, $part) if ($part->{TYPE} eq "BINARY");
		check_target($INPUT, $part) if ($part->{TYPE} eq "TARGET");
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
