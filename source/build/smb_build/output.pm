###########################################################
### SMB Build System					###
### - the output generating functions			###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Copyright (C) Jelmer Vernooij 2004	###
###  Released under the GNU GPL				###
###########################################################

package output;
use Data::Dumper;
use strict;

sub generate_objlist($)
{
	my $subsys = shift;

	$subsys->{OUTPUT} = "\$($subsys->{TYPE}_$subsys->{NAME}_OBJS)";
}

sub generate_shared_library($)
{
	my $lib = shift;

	@{$lib->{DEPEND_LIST}} = ("\$($lib->{TYPE}_$lib->{NAME}\_OBJS)");
	@{$lib->{LINK_LIST}} = ("\$($lib->{TYPE}_$lib->{NAME}\_OBJS)");
	$lib->{LIBRARY_NAME} = $lib->{NAME}.".so";
	$lib->{LIBRARY_SONAME} = $lib->{LIBRARY_NAME}.".$lib->{MAJOR_VERSION}";
	$lib->{LIBRARY_REALNAME} = $lib->{LIBRARY_SONAME}.".$lib->{MINOR_VERSION}.$lib->{RELEASE_VERSION}";
	
	$lib->{OUTPUT} = "bin/$lib->{LIBRARY_SONAME}";
}

sub generate_static_library($)
{
	my $lib = shift;

	@{$lib->{DEPEND_LIST}} = ("\$($lib->{TYPE}_$lib->{NAME}\_OBJS)");

	$lib->{LIBRARY_NAME} = $lib->{NAME}.".a";
	@{$lib->{LINK_LIST}} = ("\$($lib->{TYPE}_$lib->{NAME}\_OBJS)");
	@{$lib->{LINK_FLAGS}} = ();

	$lib->{OUTPUT} = $lib->{LIBRARY_NAME};
}

sub generate_binary($)
{
	my $bin = shift;

	@{$bin->{DEPEND_LIST}} = ("\$($bin->{TYPE}_$bin->{NAME}\_OBJS)");
	@{$bin->{LINK_LIST}} = ("\$($bin->{TYPE}_$bin->{NAME}\_OBJS)");
	@{$bin->{LINK_FLAGS}} = ();

	$bin->{OUTPUT} = "bin/$bin->{NAME}";
	$bin->{BINARY} = $bin->{NAME};
}

sub create_output($)
{
	my $depend = shift;
	my %output = ();
	my $part;

	$depend->{PROTO}{OUTPUT_TYPE} = "OBJLIST";
	$depend->{PROTO}{TYPE} = "PROTO";
	$depend->{PROTO}{NAME} = "PROTO";
	
	foreach $part (values %{$depend}) {
		next if not defined($part->{OUTPUT_TYPE});

		generate_binary($part) if $part->{OUTPUT_TYPE} eq "BINARY";
		generate_objlist($part) if $part->{OUTPUT_TYPE} eq "OBJLIST";
		generate_shared_library($part) if $part->{TYPE} eq "SHARED_LIBRARY";
		generate_static_library($part) if $part->{TYPE} eq "STATIC_LIBRARY";

		# Combine object lists
		push(@{$part->{OBJ_LIST}}, @{$part->{INIT_OBJ_FILES}}) if defined($part->{INIT_OBJ_FILES});
		push(@{$part->{OBJ_LIST}}, @{$part->{ADD_OBJ_FILES}}) if defined($part->{ADD_OBJ_FILES});
		push(@{$part->{OBJ_LIST}}, @{$part->{OBJ_FILES}}) if defined($part->{OBJ_FILES});

		push(@{$depend->{PROTO}{OBJ_LIST}}, @{$part->{OBJ_LIST}}) if ((not defined ($part->{NOPROTO}) or $part->{NOPROTO} eq "NO") and defined(@{$part->{OBJ_LIST}}));
	}

	foreach $part (values %{$depend}) {
		next if not defined($part->{OUTPUT_TYPE});

		# Always import the CFLAGS and CPPFLAGS of the unique dependencies
		foreach my $elem (values %{$part->{UNIQUE_DEPENDENCIES}}) {
			next if $elem == $part;

			push(@{$part->{CPPFLAGS}}, @{$elem->{CPPFLAGS}}) if defined(@{$elem->{CPPFLAGS}});
			push(@{$part->{CFLAGS}}, @{$elem->{CFLAGS}}) if defined(@{$elem->{CFLAGS}});
			push(@{$part->{DEPEND_LIST}}, $elem->{OUTPUT}) if defined($elem->{OUTPUT});
			push(@{$part->{LINK_LIST}}, $elem->{OUTPUT}) if defined($elem->{OUTPUT});
			push(@{$part->{LINK_LIST}}, @{$elem->{LIBS}}) if defined($elem->{LIBS});
			push(@{$part->{LINK_FLAGS}},@{$elem->{LDFLAGS}}) if defined($elem->{LDFLAGS});

			push(@{$part->{MODULE_INIT_FUNCTIONS}}, $elem->{INIT_FUNCTION}) if 
				$elem->{TYPE} eq "MODULE" and 
				defined($elem->{INIT_FUNCTION}) and
				$elem->{INIT_FUNCTION} ne "" and 
				$elem->{SUBSYSTEM} eq $part->{NAME};

			push(@{$part->{SUBSYSTEM_INIT_FUNCTIONS}}, $elem->{INIT_FUNCTION}) if 
				$part->{OUTPUT_TYPE} eq "BINARY" and 
				$elem->{TYPE} eq "SUBSYSTEM" and
				defined($elem->{INIT_FUNCTION}) and 
				$elem->{INIT_FUNCTION} ne "";
		}
	}

	print Data::Dumper::Dumper($depend);

	return %{$depend};
}

1;
