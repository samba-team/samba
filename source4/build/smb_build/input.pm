# Samba Build System
# - the input checking functions
#
#  Copyright (C) Stefan (metze) Metzmacher 2004
#  Copyright (C) Jelmer Vernooij 2004
#  Released under the GNU GPL

use smb_build::config;
use strict;
package smb_build::input;

my $srcdir = $config::config{srcdir};

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

sub add_libreplace($)
{
	my ($part) = @_;

	return if ($part->{NAME} eq "LIBREPLACE");
	return if ($part->{NAME} eq "LIBREPLACE_HOSTCC");
	return if ($part->{NAME} eq "REPLACE_READDIR");

	foreach my $n (@{$part->{PRIVATE_DEPENDENCIES}}) {
		return if ($n eq "LIBREPLACE");
		return if ($n eq "LIBREPLACE_HOSTCC");
	}
	foreach my $n (@{$part->{PUBLIC_DEPENDENCIES}}) {
		return if ($n eq "LIBREPLACE");
		return if ($n eq "LIBREPLACE_HOSTCC");
	}

	if (defined($part->{USE_HOSTCC}) && $part->{USE_HOSTCC} eq "YES") {
		unshift (@{$part->{PRIVATE_DEPENDENCIES}}, "LIBREPLACE_HOSTCC");
	} else {
		unshift (@{$part->{PRIVATE_DEPENDENCIES}}, "LIBREPLACE");
	}
}

sub check_subsystem($$$)
{
	my ($INPUT, $subsys, $default_ot) = @_;
	return if ($subsys->{ENABLE} ne "YES");
	
	unless(defined($subsys->{OUTPUT_TYPE})) {
		$subsys->{OUTPUT_TYPE} = $default_ot;
	}
	add_libreplace($subsys);
}

sub check_module($$$)
{
	my ($INPUT, $mod, $default_ot) = @_;

	die("Module $mod->{NAME} does not have a SUBSYSTEM set") if not defined($mod->{SUBSYSTEM});

	my $use_default = 0;
	
	if (not exists($INPUT->{$mod->{SUBSYSTEM}}{INIT_FUNCTIONS})) {
		$INPUT->{$mod->{SUBSYSTEM}}{INIT_FUNCTIONS} = [];
	}

	if (!(defined($INPUT->{$mod->{SUBSYSTEM}}))) {
		$mod->{ENABLE} = "NO";
		return;
	}

	return if ($mod->{ENABLE} ne "YES");

	if (exists($INPUT->{$mod->{SUBSYSTEM}}{INIT_FUNCTION_TYPE})) {
		$mod->{INIT_FUNCTION_TYPE} = $INPUT->{$mod->{SUBSYSTEM}}{INIT_FUNCTION_TYPE};
	} else {
		$mod->{INIT_FUNCTION_TYPE} = "NTSTATUS (*) (void)";
	}

	if (not defined($mod->{OUTPUT_TYPE})) {
		$mod->{OUTPUT_TYPE} = $default_ot;
	}

	if (grep(/SHARED_LIBRARY/, @{$mod->{OUTPUT_TYPE}})) {
		$mod->{INSTALLDIR} = "MODULESDIR/$mod->{SUBSYSTEM}";
		push (@{$mod->{PRIVATE_DEPENDENCIES}}, $mod->{SUBSYSTEM});
	} 
	if (grep(/INTEGRATED/, @{$mod->{OUTPUT_TYPE}})) {
		push (@{$INPUT->{$mod->{SUBSYSTEM}}{INIT_FUNCTIONS}}, $mod->{INIT_FUNCTION}) if defined($mod->{INIT_FUNCTION});
	}
	add_libreplace($mod);
}

sub check_library($$$)
{
	my ($INPUT, $lib, $default_ot) = @_;

	return if ($lib->{ENABLE} ne "YES");

	$lib->{OUTPUT_TYPE} = $default_ot;

	if (defined($lib->{VERSION}) and not defined($lib->{SO_VERSION})) {
		print "$lib->{NAME}: Please specify SO_VERSION when specifying VERSION\n";
		return;
	}

	if (defined($lib->{SO_VERSION}) and not defined($lib->{VERSION})) {
		print "$lib->{NAME}: Please specify VERSION when specifying SO_VERSION\n";
		return;
	}

	unless (defined($lib->{INIT_FUNCTION_TYPE})) {
		$lib->{INIT_FUNCTION_TYPE} = "NTSTATUS (*) (void)";
	}

	$lib->{INSTALLDIR} = "LIBDIR";
	add_libreplace($lib);
}

sub check_binary($$)
{
	my ($INPUT, $bin) = @_;

	return if ($bin->{ENABLE} ne "YES");

	($bin->{BINARY} = (lc $bin->{NAME})) if not defined($bin->{BINARY});

	$bin->{OUTPUT_TYPE} = ["BINARY"];
	add_libreplace($bin);
}

sub import_integrated($$)
{
	my ($lib, $depend) = @_;

	foreach my $mod (values %$depend) {
		next if(not defined($mod->{OUTPUT_TYPE}));
		next if(not grep(/INTEGRATED/, @{$mod->{OUTPUT_TYPE}}));
		next if(not defined($mod->{SUBSYSTEM}));
		next if($mod->{SUBSYSTEM} ne $lib->{NAME});
		next if($mod->{ENABLE} ne "YES");

		push (@{$lib->{FULL_OBJ_LIST}}, "\$($mod->{TYPE}_$mod->{NAME}_FULL_OBJ_LIST)");
		push (@{$lib->{LINK_FLAGS}}, "\$($mod->{TYPE}_$mod->{NAME}_LINK_FLAGS)");
		push (@{$lib->{PRIVATE_DEPENDENCIES}}, @{$mod->{PUBLIC_DEPENDENCIES}}) if defined($mod->{PUBLIC_DEPENDENCIES});
		push (@{$lib->{PRIVATE_DEPENDENCIES}}, @{$mod->{PRIVATE_DEPENDENCIES}}) if defined($mod->{PRIVATE_DEPENDENCIES});

		$mod->{ENABLE} = "NO";
	}
}

sub calc_unique_deps($$$$$$$$)
{
	sub calc_unique_deps($$$$$$$$);
	my ($name, $INPUT, $deps, $udeps, $withlibs, $forward, $pubonly, $busy) = @_;

	foreach my $n (@$deps) {
		die("Dependency unknown: $n") unless (defined($INPUT->{$n}));
		die("Recursive dependency: $n, list: " . join(',', @$busy)) if (grep (/^$n$/, @$busy));
		next if (grep /^$n$/, @$udeps);
		my $dep = $INPUT->{$n};

		push (@{$udeps}, $dep->{NAME}) if $forward;

 		if (defined ($dep->{OUTPUT_TYPE}) && 
			($withlibs or 
			(@{$dep->{OUTPUT_TYPE}}[0] eq "INTEGRATED") or 
			(@{$dep->{OUTPUT_TYPE}}[0] eq "STATIC_LIBRARY"))) {
				push (@$busy, $dep->{NAME});
			        calc_unique_deps($dep->{NAME}, $INPUT, $dep->{PUBLIC_DEPENDENCIES}, $udeps, $withlibs, $forward, $pubonly, $busy);
			        calc_unique_deps($dep->{NAME}, $INPUT, $dep->{PRIVATE_DEPENDENCIES}, $udeps, $withlibs, $forward, $pubonly, $busy) unless $pubonly;
				pop (@$busy);
	        }

		unshift (@{$udeps}, $dep->{NAME}) unless $forward;
	}
}

sub check($$$$$)
{
	my ($INPUT, $enabled, $subsys_ot, $lib_ot, $module_ot) = @_;

	foreach my $part (values %$INPUT) {
		unless (defined($part->{STANDARD_VISIBILITY})) {
			if ($part->{TYPE} eq "MODULE" or $part->{TYPE} eq "BINARY") {
				$part->{STANDARD_VISIBILITY} = "hidden";
			} else {
				$part->{STANDARD_VISIBILITY} = "default";
			}
		}

		unless (defined($part->{PUBLIC_HEADERS})) {
			$part->{PUBLIC_HEADERS} = [];
		}
		
		if (defined($part->{PUBLIC_PROTO_HEADER})) {
			push (@{$part->{PUBLIC_HEADERS}}, $part->{PUBLIC_PROTO_HEADER});
		}

		if (defined($enabled->{$part->{NAME}})) { 
			$part->{ENABLE} = $enabled->{$part->{NAME}};
			next;
		}
		
		unless(defined($part->{ENABLE})) {
			if ($part->{TYPE} eq "EXT_LIB") {
				$part->{ENABLE} = "NO";
			} else {
				$part->{ENABLE} = "YES";
			}
		}
	}

	foreach my $k (keys %$INPUT) {
		my $part = $INPUT->{$k};

		$part->{LINK_FLAGS} = [];
		$part->{FULL_OBJ_LIST} = ["\$($part->{TYPE}_$part->{NAME}_OBJ_LIST)"];

		check_subsystem($INPUT, $part, $subsys_ot) if ($part->{TYPE} eq "SUBSYSTEM");
		check_module($INPUT, $part, $module_ot) if ($part->{TYPE} eq "MODULE");
		check_library($INPUT, $part, $lib_ot) if ($part->{TYPE} eq "LIBRARY");
		check_binary($INPUT, $part) if ($part->{TYPE} eq "BINARY");
	}

	foreach my $part (values %$INPUT) {
		if (defined($part->{INIT_FUNCTIONS})) {
			push (@{$part->{LINK_FLAGS}}, "\$(DYNEXP)");
		}
		import_integrated($part, $INPUT);
	}

	foreach my $part (values %$INPUT) {
		$part->{UNIQUE_DEPENDENCIES_LINK} = [];
		calc_unique_deps($part->{NAME}, $INPUT, $part->{PUBLIC_DEPENDENCIES}, $part->{UNIQUE_DEPENDENCIES_LINK}, 0, 0, 0, []);
		calc_unique_deps($part->{NAME}, $INPUT, $part->{PRIVATE_DEPENDENCIES}, $part->{UNIQUE_DEPENDENCIES_LINK}, 0, 0, 0, []);
	}

	foreach my $part (values %$INPUT) {
		$part->{UNIQUE_DEPENDENCIES_COMPILE} = [];
		calc_unique_deps($part->{NAME}, $INPUT, $part->{PUBLIC_DEPENDENCIES}, $part->{UNIQUE_DEPENDENCIES_COMPILE}, 1, 1, 1, []);
		calc_unique_deps($part->{NAME}, $INPUT, $part->{PRIVATE_DEPENDENCIES}, $part->{UNIQUE_DEPENDENCIES_COMPILE}, 1, 1, 1, []);
	}

	foreach my $part (values %$INPUT) {
		$part->{UNIQUE_DEPENDENCIES_ALL} = [];
		calc_unique_deps($part->{NAME}, $INPUT, $part->{PUBLIC_DEPENDENCIES}, $part->{UNIQUE_DEPENDENCIES_ALL}, 1, 0, 0, []);
		calc_unique_deps($part->{NAME}, $INPUT, $part->{PRIVATE_DEPENDENCIES}, $part->{UNIQUE_DEPENDENCIES_ALL}, 1, 0, 0, []);
	}

	return $INPUT;
}

1;
