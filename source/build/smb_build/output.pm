###########################################################
### SMB Build System					###
### - the output generating functions			###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################

package output;
use strict;

sub _generate_ext_libs($)
{
	my $CTX = shift;

	#
	# loop over all binaries
	#
	foreach my $key (sort keys %{$CTX->{DEPEND}{EXT_LIBS}}) {
		my $NAME = $CTX->{INPUT}{EXT_LIBS}{$key}{NAME};

		#
		# set the lists
		#
		$CTX->{OUTPUT}{EXT_LIBS}{$key}{NAME} = $NAME;
		@{$CTX->{OUTPUT}{EXT_LIBS}{$key}{LIBS}} = @{$CTX->{DEPEND}{EXT_LIBS}{$key}{LIBS}};
		@{$CTX->{OUTPUT}{EXT_LIBS}{$key}{CFLAGS}} = @{$CTX->{DEPEND}{EXT_LIBS}{$key}{CFLAGS}};
		@{$CTX->{OUTPUT}{EXT_LIBS}{$key}{CPPFLAGS}} = @{$CTX->{DEPEND}{EXT_LIBS}{$key}{CPPFLAGS}};
		@{$CTX->{OUTPUT}{EXT_LIBS}{$key}{LDFLAGS}} = @{$CTX->{DEPEND}{EXT_LIBS}{$key}{LDFLAGS}};
	}

	return;	
}

sub _generate_subsystems($)
{
	my $CTX = shift;

	#
	# loop over all subsystems
	#
	foreach my $key (sort keys %{$CTX->{DEPEND}{SUBSYSTEMS}}) {
		my $NAME = $CTX->{INPUT}{SUBSYSTEMS}{$key}{NAME};
		my @OBJ_LIST = @{$CTX->{DEPEND}{SUBSYSTEMS}{$key}{OBJ_LIST}};

		if ($CTX->{INPUT}{SUBSYSTEMS}{$key}{NOPROTO} ne "YES") {
			push(@{$CTX->{OUTPUT}{PROTO}{OBJ_LIST}},"\$(SUBSYSTEM_$key\_OBJS)");
		}

		#
		# set the lists
		#
		$CTX->{OUTPUT}{SUBSYSTEMS}{$key}{NAME} = $NAME;
		@{$CTX->{OUTPUT}{SUBSYSTEMS}{$key}{OBJ_LIST}} = @OBJ_LIST;
	}

	return;	
}

sub _generate_shared_modules($)
{
	my $CTX = shift;

	#
	# loop over all shared modules
	#
	foreach my $key (sort keys %{$CTX->{DEPEND}{SHARED_MODULES}}) {
		my $NAME = $CTX->{INPUT}{MODULES}{$key}{NAME};
		my @OBJ_LIST = ();
		#
		my $MODULE = $NAME.".so";
		my @DEPEND_LIST = ("\$(MODULE_$NAME\_OBJS)");
		my @LINK_LIST = ("\$(MODULE_$NAME\_OBJS)");
		my @LINK_FLAGS = ();

		push(@{$CTX->{OUTPUT}{PROTO}{OBJ_LIST}},"\$(MODULE_$key\_OBJS)");
		push(@{$CTX->{OUTPUT}{TARGETS}{ALL}{DEPEND_LIST}},"bin/$MODULE");

		push(@OBJ_LIST,@{$CTX->{INPUT}{MODULES}{$key}{INIT_OBJ_FILES}});
		push(@OBJ_LIST,@{$CTX->{INPUT}{MODULES}{$key}{ADD_OBJ_FILES}});

		foreach my $elem (@{$CTX->{DEPEND}{SHARED_MODULES}{$key}{SUBSYSTEMS_LIST}}) {
			if (!defined($CTX->{DEPEND}{SUBSYSTEMS}{$elem})) {
				die("Shared Module[$NAME] depends on unknown Subsystem[$elem]!\n");
			}
			push(@DEPEND_LIST,"\$(SUBSYSTEM_$elem\_OBJS)");
			push(@LINK_LIST,"\$(SUBSYSTEM_$elem\_OBJS)");
		}

		foreach my $elem (@{$CTX->{DEPEND}{SHARED_MODULES}{$key}{LIBRARIES_LIST}}) {
			if (!defined($CTX->{DEPEND}{EXT_LIBS}{$elem})) {
				die("Share Module[$NAME] depends on unknown External Library[$elem]!\n");
			}
			push(@LINK_LIST,@{$CTX->{DEPEND}{EXT_LIBS}{$elem}{LIBS}});
			push(@LINK_FLAGS,@{$CTX->{DEPEND}{EXT_LIBS}{$elem}{LDFLAGS}});
		}

		#
		# set the lists
		#
		$CTX->{OUTPUT}{SHARED_MODULES}{$key}{NAME} = $NAME;
		@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{OBJ_LIST}} = @OBJ_LIST;
		#
		$CTX->{OUTPUT}{SHARED_MODULES}{$key}{MODULE} = $MODULE;
		@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{DEPEND_LIST}} = @DEPEND_LIST;
		@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{LINK_LIST}} = @LINK_LIST;
		@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{LINK_FLAGS}} = @LINK_FLAGS;
	}

	return;	
}

sub _generate_libraries($)
{
	my $CTX = shift;

	#
	# loop over all binaries
	#
	foreach my $key (sort keys %{$CTX->{DEPEND}{LIBRARIES}}) {
		my $NAME = $CTX->{INPUT}{LIBRARIES}{$key}{NAME};
		my @OBJ_LIST = @{$CTX->{INPUT}{LIBRARIES}{$key}{OBJ_FILES}};
		my $MAJOR_VERSION = $CTX->{INPUT}{LIBRARIES}{$key}{MAJOR_VERSION};
		my $MINOR_VERSION = $CTX->{INPUT}{LIBRARIES}{$key}{MINOR_VERSION};
		my $RELEASE_VERSION = $CTX->{INPUT}{LIBRARIES}{$key}{RELEASE_VERSION};
		#
		my @DEPEND_LIST = ("\$(LIBRARY_$NAME\_OBJS)");

		my $STATIC_LIBRARY_NAME = $NAME.".a";
		my @STATIC_LINK_LIST = ("\$(LIBRARY_$NAME\_OBJS)");
		my @STATIC_LINK_FLAGS = ();

		my $SHARED_LIBRARY_NAME = $NAME.".so";
		my $SHARED_LIBRARY_SONAME = $SHARED_LIBRARY_NAME.".$MAJOR_VERSION";
		my $SHARED_LIBRARY_REALNAME = $SHARED_LIBRARY_SONAME.".$MINOR_VERSION.$RELEASE_VERSION";
		my @SHARED_LINK_LIST = ("\$(LIBRARY_$NAME\_OBJS)");
		my @SHARED_LINK_FLAGS = ("\@SONAMEFLAG\@$SHARED_LIBRARY_SONAME");

		push(@{$CTX->{OUTPUT}{PROTO}{OBJ_LIST}},"\$(LIBRARY_$key\_OBJS)");
		
		#
		# not add to 'make all' for now
		#

		foreach my $elem (@{$CTX->{DEPEND}{LIBRARIES}{$key}{SUBSYSTEMS_LIST}}) {
			if (!defined($CTX->{DEPEND}{SUBSYSTEMS}{$elem})) {
				die("Library[$NAME] depends on unknown Subsystem[$elem]!\n");
			}
			push(@DEPEND_LIST,"\$(SUBSYSTEM_$elem\_OBJS)");
			push(@STATIC_LINK_LIST,"\$(SUBSYSTEM_$elem\_OBJS)");
			push(@SHARED_LINK_LIST,"\$(SUBSYSTEM_$elem\_OBJS)");
		}

		foreach my $elem (@{$CTX->{DEPEND}{LIBRARIES}{$key}{LIBRARIES_LIST}}) {
			if (!defined($CTX->{DEPEND}{EXT_LIBS}{$elem})) {
				die("Library[$NAME] depends on unknown External Library[$elem]!\n");
			}
			push(@SHARED_LINK_LIST,@{$CTX->{DEPEND}{EXT_LIBS}{$elem}{LIBS}});
			push(@SHARED_LINK_FLAGS,@{$CTX->{DEPEND}{EXT_LIBS}{$elem}{LDFLAGS}});
		}

		#
		# set the lists
		#
		$CTX->{OUTPUT}{LIBRARIES}{$key}{NAME} = $NAME;
		@{$CTX->{OUTPUT}{LIBRARIES}{$key}{OBJ_LIST}} = @OBJ_LIST;
		#
		@{$CTX->{OUTPUT}{LIBRARIES}{$key}{DEPEND_LIST}} = @DEPEND_LIST;

		$CTX->{OUTPUT}{LIBRARIES}{$key}{STATIC_LIBRARY_NAME} = $STATIC_LIBRARY_NAME;
		@{$CTX->{OUTPUT}{LIBRARIES}{$key}{STATIC_LINK_LIST}} = @STATIC_LINK_LIST;
		@{$CTX->{OUTPUT}{LIBRARIES}{$key}{STATIC_LINK_FLAGS}} = @STATIC_LINK_FLAGS;

		$CTX->{OUTPUT}{LIBRARIES}{$key}{SHARED_LIBRARY_NAME} = $SHARED_LIBRARY_NAME;
		$CTX->{OUTPUT}{LIBRARIES}{$key}{SHARED_LIBRARY_REALNAME} = $SHARED_LIBRARY_REALNAME;
		$CTX->{OUTPUT}{LIBRARIES}{$key}{SHARED_LIBRARY_SONAME} = $SHARED_LIBRARY_SONAME;
		@{$CTX->{OUTPUT}{LIBRARIES}{$key}{SHARED_LINK_LIST}} = @SHARED_LINK_LIST;
		@{$CTX->{OUTPUT}{LIBRARIES}{$key}{SHARED_LINK_FLAGS}} = @SHARED_LINK_FLAGS;
	}

	return;
}

sub _generate_binaries($)
{
	my $CTX = shift;

	#
	# loop over all binaries
	#
	foreach my $key (sort keys %{$CTX->{DEPEND}{BINARIES}}) {
		my $NAME = $CTX->{INPUT}{BINARIES}{$key}{NAME};
		my @OBJ_LIST = @{$CTX->{INPUT}{BINARIES}{$key}{OBJ_FILES}};
		#
		my $BINARY = $NAME;
		my @DEPEND_LIST = ("\$(BINARY_$NAME\_OBJS)");
		my @LINK_LIST = ("\$(BINARY_$NAME\_OBJS)");
		my @LINK_FLAGS = ();

		push(@{$CTX->{OUTPUT}{PROTO}{OBJ_LIST}},"\$(BINARY_$key\_OBJS)");
		push(@{$CTX->{OUTPUT}{TARGETS}{ALL}{DEPEND_LIST}},"bin/$BINARY");

		foreach my $elem (@{$CTX->{DEPEND}{BINARIES}{$key}{SUBSYSTEMS_LIST}}) {
			if (!defined($CTX->{DEPEND}{SUBSYSTEMS}{$elem})) {
				die("Binary[$NAME] depends on unknown Subsystem[$elem]!\n");
			}
			push(@DEPEND_LIST,"\$(SUBSYSTEM_$elem\_OBJS)");
			push(@LINK_LIST,"\$(SUBSYSTEM_$elem\_OBJS)");
		}

		foreach my $elem (@{$CTX->{DEPEND}{BINARIES}{$key}{LIBRARIES_LIST}}) {
			if (!defined($CTX->{DEPEND}{EXT_LIBS}{$elem})) {
				die("Binary[$NAME] depends on unknown External Library[$elem]!\n");
			}
			push(@LINK_LIST,@{$CTX->{DEPEND}{EXT_LIBS}{$elem}{LIBS}});
			push(@LINK_FLAGS,@{$CTX->{DEPEND}{EXT_LIBS}{$elem}{LDFLAGS}});
		}

		# Export all symbols...
		push(@LINK_FLAGS,@{$CTX->{BUILD_ENV}{LD}{DYNEXP}});

		#
		# set the lists
		#
		$CTX->{OUTPUT}{BINARIES}{$key}{NAME} = $NAME;
		@{$CTX->{OUTPUT}{BINARIES}{$key}{OBJ_LIST}} = @OBJ_LIST;
		#
		$CTX->{OUTPUT}{BINARIES}{$key}{BINARY} = $BINARY;
		@{$CTX->{OUTPUT}{BINARIES}{$key}{DEPEND_LIST}} = @DEPEND_LIST;
		@{$CTX->{OUTPUT}{BINARIES}{$key}{LINK_LIST}} = @LINK_LIST;
		@{$CTX->{OUTPUT}{BINARIES}{$key}{LINK_FLAGS}} = @LINK_FLAGS;
	}

	return;	
}

###########################################################
# This function generates the output 
#
# create_output($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
sub create_output($)
{
	my $CTX = shift;

	$CTX->{OUTPUT}{PROTO} = ();
	@{$CTX->{OUTPUT}{PROTO}{OBJ_LIST}} = ();

	$CTX->{OUTPUT}{TARGETS}{ALL} = ();
	$CTX->{OUTPUT}{TARGETS}{ALL}{TARGET} = "all";
	@{$CTX->{OUTPUT}{TARGETS}{ALL}{DEPEND_LIST}} = ();

	_generate_ext_libs($CTX);

	_generate_subsystems($CTX);

	_generate_shared_modules($CTX);

	_generate_libraries($CTX);

	_generate_binaries($CTX);

	return;
}

1;
