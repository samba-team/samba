###########################################################
### SMB Build System					###
### - the input checking functions			###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Copyright (C) Jelmer Vernooij 2004	###
###  Released under the GNU GPL				###
###########################################################

use strict;
package input;

my $subsystem_output_type = "OBJLIST";
our $srcdir = ".";

sub strtrim($)
{
	my $str = shift;
	my @ar = ();

	$str =~ s/^[\t\n ]*//g;

	$str =~ s/[\t\n ]*$//g;

	return $str;
}

sub str2array($)
{
	my $str = shift;
	my @ar = ();

	$str =~ s/^[\t\n ]*//g;

	$str =~ s/[\t\n ]*$//g;

	$str =~ s/([\t\n ]+)/ /g;

	if (length($str)==0) {
		return ();
	}

	@ar = split(/[ \t\n]/,$str);

	return @ar;
}

sub check_subsystem($$)
{
	my $CTX = shift;
	my $subsys = shift;
	if ($subsys->{ENABLE} ne "YES") {
		printf("Subsystem: %s disabled!\n",$subsys->{NAME});
	}
	
	$subsys->{OUTPUT_TYPE} = $subsystem_output_type;
}

sub check_module($$)
{
	my $CTX = shift;
	my $mod = shift;

	die("Module $mod->{NAME} does not have a SUBSYSTEM set") if not defined($mod->{SUBSYSTEM});

	($mod->{DEFAULT_BUILD} = "STATIC") if not defined($mod->{DEFAULT_BUILD});
	
	my $use_default = 0;

	$mod->{SUBSYSTEM} = join(' ', @{$mod->{SUBSYSTEM}});

	if (!(defined($CTX->{INPUT}{$mod->{SUBSYSTEM}}))) {
		$mod->{BUILD} = "NOT";
		$mod->{ENABLE} = "NO";
		printf("Module: %s...PARENT SUBSYSTEM ($mod->{SUBSYSTEM}) DISABLED\n",$mod->{NAME});
		return;
	}

	if (not defined($mod->{CHOSEN_BUILD}) or $mod->{CHOSEN_BUILD} eq "DEFAULT") {
		$mod->{CHOSEN_BUILD} = $mod->{DEFAULT_BUILD};
	}

	if ($mod->{CHOSEN_BUILD} eq "SHARED") {
		$mod->{ENABLE} = "YES";
		$mod->{OUTPUT_TYPE} = "SHARED_LIBRARY";
		push (@{$mod->{REQUIRED_SUBSYSTEMS}}, $mod->{SUBSYSTEM});
		printf("Module: %s...shared\n",$mod->{NAME});
	} elsif ($mod->{CHOSEN_BUILD} eq "STATIC") {
		$mod->{ENABLE} = "YES";
		push (@{$CTX->{INPUT}{$mod->{SUBSYSTEM}}{REQUIRED_SUBSYSTEMS}}, $mod->{NAME});
		printf("Module: %s...static\n",$mod->{NAME});
		$mod->{OUTPUT_TYPE} = $subsystem_output_type;
	} else {
		$mod->{ENABLE} = "NO";
		printf("Module: %s...not\n",$mod->{NAME});
		return;
	}
}

sub check_library($$)
{
	my $CTX = shift;
	my $lib = shift;

	if ($lib->{ENABLE} ne "YES") {
		printf("Library: %s...disabled\n",$lib->{NAME});
		return;
	}

	$lib->{OUTPUT_TYPE} = "SHARED_LIBRARY";
}

sub check_binary($$)
{
	my $CTX = shift;
	my $bin = shift;

	if ($bin->{ENABLE} ne "YES") {
		printf("Binary: %s...disabled\n",$bin->{NAME});
		return;
	}

	($bin->{BINARY} = (lc $bin->{NAME})) if not defined($bin->{BINARY});

	$bin->{OUTPUT_TYPE} = "BINARY";
}

sub calc_unique_deps
{
	my $deps = shift;
	my $udeps = shift;

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
# check_input($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
sub check($)
{
	my $CTX = shift;

	($subsystem_output_type = $ENV{SUBSYSTEM_OUTPUT_TYPE}) if (defined($ENV{"SUBSYSTEM_OUTPUT_TYPE"}));

	foreach my $part (values %{$CTX->{INPUT}}) {
		($part->{ENABLE} = "YES") if not defined($part->{ENABLE});
	}

	foreach my $part (values %{$CTX->{INPUT}}) {
		check_subsystem($CTX, $part) if ($part->{TYPE} eq "SUBSYSTEM");
		check_module($CTX, $part) if ($part->{TYPE} eq "MODULE");
		check_library($CTX, $part) if ($part->{TYPE} eq "LIBRARY");
		check_binary($CTX, $part) if ($part->{TYPE} eq "BINARY");

		#FIXME: REQUIRED_LIBRARIES needs to go
		if (defined($part->{REQUIRED_LIBRARIES})) {
			push(@{$part->{REQUIRED_SUBSYSTEMS}}, @{$part->{REQUIRED_LIBRARIES}});
			delete ($part->{REQUIRED_LIBRARIES});
		}
	}

	my %depend = %{$CTX->{INPUT}};

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

	return %depend;
}

1;
