###########################################################
### SMB Build System					###
### - the dependency calculation functions		###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################

###########################################################
# This function creates the dependencies for shared modules
# _do_depend_shared_modules($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
sub _do_depend_shared_modules($)
{
	my $CTX = shift;

	$CTX->{OUTPUT}{SHARED_MODULES} = $CTX->{INPUT}{MODULES};

	return;
}

###########################################################
# This function creates the dependencies for subsystems
# _do_depend_subsystems($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
sub _do_depend_subsystems($)
{
	my $CTX = shift;

	$CTX->{OUTPUT}{SUBSYSTEMS} = $CTX->{INPUT}{SUBSYSTEMS};

	return;
}

###########################################################
# This function creates the dependencies for libraries
# _do_depend_libraries($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
sub _do_depend_libraries($)
{
	my $CTX = shift;

	$CTX->{OUTPUT}{LIBRARIES} = $CTX->{INPUT}{LIBRARIES};

	return;
}

###########################################################
# This function creates the dependencies for binaries
# _do_depend_binaries($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
sub _do_depend_binaries($)
{
	my $CTX = shift;

	$CTX->{OUTPUT}{BINARIES} = $CTX->{INPUT}{BINARIES};

	return;
}

###########################################################
# This function creates the dependency tree from the SMB_BUILD 
# context
# create_depend_output($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
sub create_depend_output($)
{
	my $CTX = shift;

	_do_depend_shared_modules($CTX);

	_do_depend_subsystems($CTX);

	_do_depend_libraries($CTX);

	_do_depend_binaries($CTX);

	$CTX->{OUTPUT}{PROTO} = ();
	@{$CTX->{OUTPUT}{PROTO}{OBJ_LIST}} = ();

	foreach my $key (sort keys %{$CTX->{OUTPUT}{SUBSYSTEMS}}) {
		my $name = $CTX->{OUTPUT}{SUBSYSTEMS}{$key}{NAME};

		@{$CTX->{OUTPUT}{SUBSYSTEMS}{$key}{OBJ_LIST}} = ();
		push(@{$CTX->{OUTPUT}{SUBSYSTEMS}{$key}{OBJ_LIST}},@{$CTX->{OUTPUT}{SUBSYSTEMS}{$key}{INIT_OBJ_FILES}});
		push(@{$CTX->{OUTPUT}{SUBSYSTEMS}{$key}{OBJ_LIST}},@{$CTX->{OUTPUT}{SUBSYSTEMS}{$key}{ADD_OBJ_FILES}});

		push(@{$CTX->{OUTPUT}{PROTO}{OBJ_LIST}},"\$(SUBSYSTEM_$name\_OBJS)");
	}

	foreach my $key (sort keys %{$CTX->{OUTPUT}{SHARED_MODULES}}) {
		if ($CTX->{OUTPUT}{SHARED_MODULES}{$key}{BUILD} eq "NOT" ) {
			next;
		}

		my $name = $CTX->{OUTPUT}{SHARED_MODULES}{$key}{NAME};

		@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{OBJ_LIST}} = ();
		push(@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{OBJ_LIST}},@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{INIT_OBJ_FILES}});
		push(@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{OBJ_LIST}},@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{ADD_OBJ_FILES}});

		push(@{$CTX->{OUTPUT}{PROTO}{OBJ_LIST}},"\$(MODULE_$name\_OBJS)");
	}

	foreach my $key (sort keys %{$CTX->{OUTPUT}{LIBRARIES}}) {
		my $name = $CTX->{OUTPUT}{LIBRARIES}{$key}{NAME};

		@{$CTX->{OUTPUT}{LIBRARIES}{$key}{OBJ_LIST}} = @{$CTX->{OUTPUT}{LIBRARIES}{$key}{OBJ_FILES}};

		push(@{$CTX->{OUTPUT}{PROTO}{OBJ_LIST}},"\$(LIBRARY_$name\_OBJS)");
	}

	foreach my $key (sort keys %{$CTX->{OUTPUT}{BINARIES}}) {
		my $name = $CTX->{OUTPUT}{BINARIES}{$key}{NAME};

		@{$CTX->{OUTPUT}{BINARIES}{$key}{OBJ_LIST}} = @{$CTX->{OUTPUT}{BINARIES}{$key}{OBJ_FILES}};

		push(@{$CTX->{OUTPUT}{PROTO}{OBJ_LIST}},"\$(BINARY_$name\_OBJS)");

	}

#########################################################
	$CTX->{OUTPUT}{TARGETS}{ALL} = ();
	$CTX->{OUTPUT}{TARGETS}{ALL}{TARGET} = "all";
	@{$CTX->{OUTPUT}{TARGETS}{ALL}{DEPEND_LIST}} = ();

	foreach my $key (sort keys %{$CTX->{OUTPUT}{SHARED_MODULES}}) {
		my $name = $CTX->{OUTPUT}{SHARED_MODULES}{$key}{NAME};

		$CTX->{OUTPUT}{SHARED_MODULES}{$key}{MODULE} = $CTX->{OUTPUT}{SHARED_MODULES}{$key}{NAME}.".so";
		
		push(@{$CTX->{OUTPUT}{TARGETS}{ALL}{DEPEND_LIST}},"bin/".$CTX->{OUTPUT}{SHARED_MODULES}{$key}{MODULE});

		@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{DEPEND_LIST}} = ();
		push(@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{DEPEND_LIST}},"\$(MODULE_$name\_OBJS)");

		@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{LINK_LIST}} = ();
		push(@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{LINK_LIST}},"\$(MODULE_$name\_OBJS)");
		push(@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{LINK_LIST}},"\$(MODULE_$name\_LIBS)");

		$CTX->{OUTPUT}{SHARED_MODULES}{$key}{LINK_FLAGS} = "-Wl,-soname=$name.so";
	}

	foreach my $key (sort keys %{$CTX->{OUTPUT}{BINARIES}}) {
		my $name = $CTX->{OUTPUT}{BINARIES}{$key}{NAME};

		$CTX->{OUTPUT}{BINARIES}{$key}{BINARY} = $CTX->{OUTPUT}{BINARIES}{$key}{NAME};

		@{$CTX->{OUTPUT}{BINARIES}{$key}{DEPEND_LIST}} = ();
		push(@{$CTX->{OUTPUT}{BINARIES}{$key}{DEPEND_LIST}},"\$(BINARY_$name\_DEPEND_LIST)");

		@{$CTX->{OUTPUT}{BINARIES}{$key}{LINK_LIST}} = ();
		push(@{$CTX->{OUTPUT}{BINARIES}{$key}{LINK_LIST}},"\$(BINARY_$name\_LINK_LIST)");

		$CTX->{OUTPUT}{BINARIES}{$key}{LINK_FLAGS} = "";
	}

	return;
}
