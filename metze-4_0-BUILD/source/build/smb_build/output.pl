###########################################################
### SMB Build System					###
### - the output generating functions			###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################

sub _generate_subsystems($)
{
	my $CTX = shift;

	#
	# loop over all binaries
	#
	foreach my $key (sort keys %{$CTX->{DEPEND}{SUBSYSTEMS}}) {
		my $NAME = $CTX->{INPUT}{SUBSYSTEMS}{$key}{NAME};
		my @OBJ_LIST = @{$CTX->{DEPEND}{SUBSYSTEMS}{$key}{OBJ_LIST}};
		my @LIB_LIST = ();

		push(@{$CTX->{OUTPUT}{PROTO}{OBJ_LIST}},"\$(SUBSYSTEM_$key\_OBJS)");

		#
		# set the lists
		#
		$CTX->{OUTPUT}{SUBSYSTEMS}{$key}{NAME} = $NAME;
		@{$CTX->{OUTPUT}{SUBSYSTEMS}{$key}{OBJ_LIST}} = @OBJ_LIST;
		@{$CTX->{OUTPUT}{SUBSYSTEMS}{$key}{LIB_LIST}} = @LIB_LIST;
	}

	return;	
}

sub _generate_shared_modules($)
{
	my $CTX = shift;

	#
	# loop over all binaries
	#
	foreach my $key (sort keys %{$CTX->{DEPEND}{SHARED_MODULES}}) {
		my $NAME = $CTX->{INPUT}{MODULES}{$key}{NAME};
		my @OBJ_LIST = ();
		my @LIB_LIST = ();
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
			push(@DEPEND_LIST,"\$(SUBSYSTEM_$elem\_OBJS)");
			push(@LINK_LIST,"\$(SUBSYSTEM_$elem\_OBJS)");
		}

		foreach my $elem (@{$CTX->{DEPEND}{SHARED_MODULES}{$key}{LIBRARIES_LIST}}) {
			#push(@LINK_FLAGS,"\$(EXTLIB_$elem\_FLAGS");
		}

		#
		# set the lists
		#
		$CTX->{OUTPUT}{SHARED_MODULES}{$key}{NAME} = $NAME;
		@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{OBJ_LIST}} = @OBJ_LIST;
		@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{LIB_LIST}} = @LIB_LIST;
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
		my @LIB_LIST = ();
		#
		my $BINARY = $NAME;
		my @DEPEND_LIST = ("\$(BINARY_$NAME\_OBJS)");
		my @LINK_LIST = ("\$(BINARY_$NAME\_OBJS)");
		my @LINK_FLAGS = ();

		push(@{$CTX->{OUTPUT}{PROTO}{OBJ_LIST}},"\$(BINARY_$key\_OBJS)");
		push(@{$CTX->{OUTPUT}{TARGETS}{ALL}{DEPEND_LIST}},"bin/$BINARY");

		foreach my $elem (@{$CTX->{DEPEND}{BINARIES}{$key}{SUBSYSTEMS_LIST}}) {
			push(@DEPEND_LIST,"\$(SUBSYSTEM_$elem\_OBJS)");
			push(@LINK_LIST,"\$(SUBSYSTEM_$elem\_OBJS)");
		}

		foreach my $elem (@{$CTX->{DEPEND}{BINARIES}{$key}{LIBRARIES_LIST}}) {
			#push(@LINK_FLAGS,"\$(EXTLIB_$elem\_FLAGS");
		}

		#
		# set the lists
		#
		$CTX->{OUTPUT}{BINARIES}{$key}{NAME} = $NAME;
		@{$CTX->{OUTPUT}{BINARIES}{$key}{OBJ_LIST}} = @OBJ_LIST;
		@{$CTX->{OUTPUT}{BINARIES}{$key}{LIB_LIST}} = @LIB_LIST;
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

	_generate_subsystems($CTX);

	_generate_shared_modules($CTX);

	_generate_libraries($CTX);

	_generate_binaries($CTX);

	return;
}
