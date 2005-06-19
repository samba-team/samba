###########################################################
### SMB Build System					###
### - the output generating functions			###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Copyright (C) Jelmer Vernooij 2004	###
###  Released under the GNU GPL				###
###########################################################

package output;
use strict;

sub generate_objlist($)
{
	my $subsys = shift;

	$subsys->{TARGET} = "bin/.$subsys->{TYPE}_$subsys->{NAME}";
	$subsys->{OUTPUT} = "\$($subsys->{TYPE}_$subsys->{NAME}_OBJS)";
}

sub generate_shared_library($)
{
	my $lib = shift;

	@{$lib->{DEPEND_LIST}} = ();
	@{$lib->{LINK_LIST}} = ("\$($lib->{TYPE}_$lib->{NAME}\_OBJS)");
	$lib->{LIBRARY_NAME} = lc($lib->{NAME}).".so";
	$lib->{TARGET} = "bin/lib$lib->{LIBRARY_NAME}";
	if (defined($lib->{MAJOR_VERSION})) {
		$lib->{LIBRARY_SONAME} = $lib->{LIBRARY_NAME}.".$lib->{MAJOR_VERSION}";
		$lib->{LIBRARY_REALNAME} = $lib->{LIBRARY_SONAME}.".$lib->{MINOR_VERSION}.$lib->{RELEASE_VERSION}";
		$lib->{TARGET} = "bin/lib$lib->{LIBRARY_REALNAME}";
		@{$lib->{LINK_FLAGS}} = ("\@SONAMEFLAG\@$lib->{LIBRARY_SONAME}");
	}
	$lib->{OUTPUT} = "-l".lc($lib->{NAME});
}

sub generate_static_library($)
{
	my $lib = shift;

	@{$lib->{DEPEND_LIST}} = ();

	$lib->{LIBRARY_NAME} = lc($lib->{NAME}).".a";
	@{$lib->{LINK_LIST}} = ("\$($lib->{TYPE}_$lib->{NAME}\_OBJS)");
	@{$lib->{LINK_FLAGS}} = ();

	$lib->{TARGET} = "bin/lib$lib->{LIBRARY_NAME}";
	$lib->{OUTPUT} = "-l".lc($lib->{NAME});
}

sub generate_binary($)
{
	my $bin = shift;

	@{$bin->{DEPEND_LIST}} = ();
	@{$bin->{LINK_LIST}} = ("\$($bin->{TYPE}_$bin->{NAME}\_OBJS)");
	@{$bin->{LINK_FLAGS}} = ();

	$bin->{TARGET} = $bin->{OUTPUT} = "bin/$bin->{NAME}";
	$bin->{BINARY} = $bin->{NAME};
}

sub create_output($)
{
	my $depend = shift;
	my $part;

	$depend->{PROTO} = {
		OUTPUT_TYPE => "OBJLIST",
		TYPE => "PROTO",
		NAME => "PROTO",
		OBJ_LIST => []
	};

	$depend->{ALL_OBJS} = {
		OUTPUT_TYPE => "OBJLIST",
		TYPE => "",
		NAME => "ALL_OBJS",
		OBJ_LIST => []
	};

	foreach $part (values %{$depend}) {
		next if $part->{NAME} eq "PROTO";
		next if $part->{NAME} eq "ALL_OBJS";
		next if not defined($part->{OUTPUT_TYPE});

		generate_binary($part) if $part->{OUTPUT_TYPE} eq "BINARY";
		generate_objlist($part) if $part->{OUTPUT_TYPE} eq "OBJLIST";
		generate_shared_library($part) if $part->{OUTPUT_TYPE} eq "SHARED_LIBRARY";
		generate_static_library($part) if $part->{OUTPUT_TYPE} eq "STATIC_LIBRARY";

		# Combine object lists
		push(@{$part->{OBJ_LIST}}, @{$part->{INIT_OBJ_FILES}}) if defined($part->{INIT_OBJ_FILES});
		push(@{$part->{OBJ_LIST}}, @{$part->{ADD_OBJ_FILES}}) if defined($part->{ADD_OBJ_FILES});
		push(@{$part->{OBJ_LIST}}, @{$part->{OBJ_FILES}}) if defined($part->{OBJ_FILES});

		push(@{$depend->{ALL_OBJS}->{OBJ_LIST}}, @{$part->{OBJ_LIST}}) if (defined(@{$part->{OBJ_LIST}}));
		
		if ((not defined ($part->{NOPROTO})) or ($part->{NOPROTO} eq "NO")) {
			push(@{$depend->{PROTO}->{OBJ_LIST}}, @{$part->{OBJ_LIST}}) if (defined(@{$part->{OBJ_LIST}}));
		}
	}

	foreach $part (values %{$depend}) {
		next if not defined($part->{OUTPUT_TYPE});

		foreach (@{$part->{DEPENDENCIES}}) {
			my $elem = $$_;
			push(@{$part->{DEPEND_LIST}}, $elem->{TARGET}) if defined($elem->{TARGET});
		}

		# Always import the CFLAGS and CPPFLAGS of the unique dependencies
		foreach my $elem (values %{$part->{UNIQUE_DEPENDENCIES}}) {
			next if $elem == $part;

			push(@{$part->{CPPFLAGS}}, @{$elem->{CPPFLAGS}}) if defined(@{$elem->{CPPFLAGS}});
			push(@{$part->{CFLAGS}}, @{$elem->{CFLAGS}}) if defined(@{$elem->{CFLAGS}});
			push(@{$part->{LINK_LIST}}, $elem->{OUTPUT}) if defined($elem->{OUTPUT});
			push(@{$part->{LINK_FLAGS}}, @{$elem->{LIBS}}) if defined($elem->{LIBS});
			push(@{$part->{LINK_FLAGS}},@{$elem->{LDFLAGS}}) if defined($elem->{LDFLAGS});

			push(@{$part->{SUBSYSTEM_INIT_FUNCTIONS}}, $elem->{INIT_FUNCTION}) if 
				$part->{OUTPUT_TYPE} eq "BINARY" and 
				defined($elem->{INIT_FUNCTION}) and 
				$elem->{INIT_FUNCTION} ne "" and
				$part->{OUTPUT_TYPE} ne "SHARED_LIBRARY";
		}
	}

	return $depend;
}

1;
