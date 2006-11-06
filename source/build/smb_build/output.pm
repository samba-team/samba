# SMB Build System
# - the output generating functions
#
#  Copyright (C) Stefan (metze) Metzmacher 2004
#  Copyright (C) Jelmer Vernooij 2004
#  Released under the GNU GPL

package output;
use strict;

sub add_dir($$)
{
	my ($dir,$files) = @_;
	my @ret = ();
	my $dirsep = "/";

	$dir =~ s/^\.$//g;
	$dir =~ s/^\.\///g;

	$dirsep = "" if ($dir eq "");
	
	foreach (@$files) {
		if (substr($_, 0, 1) ne "\$") {
			$_ = "$dir$dirsep$_";
			s/([^\/\.]+)\/\.\.\///g;
			s/([^\/\.]+)\/\.\.\///g;
		}
		push (@ret, $_);
	}
	
	return @ret;
}

sub generate_shared_library($)
{
	my $lib = shift;
	my $link_name;
	my $lib_name;

	$lib->{DEPEND_LIST} = [];

	$link_name = lc($lib->{NAME});
	$lib_name = $link_name;

	if ($lib->{TYPE} eq "LIBRARY") {
		$link_name = $lib->{NAME};
		$link_name =~ s/^LIB//;
		$link_name = lc($link_name);
		$lib_name = "lib$link_name";
	}

	if (defined($lib->{LIBRARY_REALNAME})) {
		$lib->{BASEDIR} =~ s/^\.\///g;
		$lib->{LIBRARY_REALNAME} = "$lib->{LIBRARY_REALNAME}";
		$lib->{SHAREDDIR} = $lib->{BASEDIR};
	} else {
		if ($lib->{TYPE} eq "MODULE") {
			$lib->{SHAREDDIR} = "bin/modules/$lib->{SUBSYSTEM}";
			$lib->{LIBRARY_REALNAME} = $link_name;
			$lib->{LIBRARY_REALNAME} =~ s/^$lib->{SUBSYSTEM}_//g;
			$lib->{LIBRARY_REALNAME}.= ".\$(SHLIBEXT)";
		} else {
			$lib->{SHAREDDIR} = "bin/shared";
			$lib->{LIBRARY_REALNAME} = "$lib_name.\$(SHLIBEXT)";
		}
	}

	if (defined($lib->{VERSION})) {
		$lib->{LIBRARY_SONAME} = "$lib->{LIBRARY_REALNAME}.$lib->{SO_VERSION}";
		$lib->{LIBRARY_REALNAME} = "$lib->{LIBRARY_REALNAME}.$lib->{VERSION}";
	} 
	
	$lib->{TARGET_SHARED_LIBRARY} = "$lib->{SHAREDDIR}/$lib->{LIBRARY_REALNAME}";
	$lib->{OUTPUT_SHARED_LIBRARY} = $lib->{TARGET_SHARED_LIBRARY};
}

sub generate_static_library($)
{
	my $lib = shift;
	my $link_name;

	$lib->{DEPEND_LIST} = [];

	$link_name = $lib->{NAME};
	$link_name =~ s/^LIB//;

	$lib->{LIBRARY_NAME} = "lib".lc($link_name).".a";

	if (defined($lib->{OBJ_FILES})) {
		$lib->{TARGET_STATIC_LIBRARY} = "bin/static/$lib->{LIBRARY_NAME}";
	} else {
		$lib->{TARGET_STATIC_LIBRARY} = "";
	}
	$lib->{OUTPUT_STATIC_LIBRARY} = $lib->{TARGET_STATIC_LIBRARY};
}

sub generate_binary($)
{
	my $bin = shift;

	$bin->{DEPEND_LIST} = [];
	push(@{$bin->{LINK_FLAGS}}, "\$($bin->{TYPE}_$bin->{NAME}\_OBJ_LIST)");

	$bin->{DEBUGDIR} = "bin/";
	$bin->{TARGET_BINARY} = $bin->{OUTPUT_BINARY} = "$bin->{DEBUGDIR}/$bin->{NAME}";
	$bin->{BINARY} = $bin->{NAME};
}

sub merge_array($$)
{
	# $dest is a reference to an array
	# $src is an array
	my ($dest, $src) = @_;

	return unless defined($src);
	return unless ($#{$src} >= 0);

	foreach my $line (@{$src}) {
		next if (grep /^$line$/, @{$$dest});
		push(@{$$dest}, $line);
	}
}

sub create_output($$)
{
	my ($depend, $config) = @_;
	my $part;

	foreach $part (values %{$depend}) {
		next unless(defined($part->{OUTPUT_TYPE}));

		# Combine object lists
		push(@{$part->{OBJ_LIST}}, add_dir($part->{BASEDIR}, $part->{OBJ_FILES})) if defined($part->{OBJ_FILES});

		generate_binary($part) if grep(/BINARY/, @{$part->{OUTPUT_TYPE}});
		generate_shared_library($part) if grep(/SHARED_LIBRARY/, @{$part->{OUTPUT_TYPE}});
		generate_static_library($part) if grep(/STATIC_LIBRARY/, @{$part->{OUTPUT_TYPE}});
		$part->{OUTPUT} = $part->{"OUTPUT_" . @{$part->{OUTPUT_TYPE}}[0]};
		$part->{TARGET} = $part->{"TARGET_" . @{$part->{OUTPUT_TYPE}}[0]};
	}

	foreach $part (values %{$depend}) {
		next if not defined($part->{OUTPUT_TYPE});

		merge_array(\$part->{FINAL_CFLAGS}, $part->{CPPFLAGS});
		merge_array(\$part->{FINAL_CFLAGS}, $part->{CFLAGS});

		foreach (reverse @{$part->{UNIQUE_DEPENDENCIES_ALL}}) {
			my $elem = $depend->{$_};
			next if $elem == $part;

			merge_array(\$part->{FINAL_CFLAGS}, $elem->{CPPFLAGS});
			merge_array(\$part->{FINAL_CFLAGS}, $elem->{CFLAGS});
		}

		# Always import the link options of the unique dependencies
		foreach (@{$part->{UNIQUE_DEPENDENCIES}}) {
			my $elem = $depend->{$_};
			next if $elem == $part;

			push(@{$part->{LINK_FLAGS}}, $elem->{OUTPUT}) if defined($elem->{OUTPUT});
			push(@{$part->{LINK_FLAGS}}, @{$elem->{LIBS}}) if defined($elem->{LIBS});
			push(@{$part->{LINK_FLAGS}},@{$elem->{LDFLAGS}}) if defined($elem->{LDFLAGS});
		    	push(@{$part->{DEPEND_LIST}}, $elem->{TARGET}) if defined($elem->{TARGET});
		}
	}

	foreach $part (values %{$depend}) {
		if (($part->{STANDARD_VISIBILITY} ne "default") and 
			($config->{visibility_attribute} eq "yes")) {
		    	push(@{$part->{FINAL_CFLAGS}}, "-fvisibility=$part->{STANDARD_VISIBILITY}");
		}
	}

	return $depend;
}

1;
