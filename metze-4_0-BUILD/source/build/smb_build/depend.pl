###########################################################
### SMB Build System					###
### - the dependency calculation functions		###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################


###########################################################
# This function creates the dependencies for subsystems
# _do_depend_subsystems($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
sub _do_depend_subsystems($)
{
	my $CTX = shift;

	#
	# loop on all subsystems
	#
	foreach my $key (sort keys %{$CTX->{INPUT}{SUBSYSTEMS}}) {
		my $name = $CTX->{INPUT}{SUBSYSTEMS}{$key}{NAME};

		#
		# skip when the subsystem was disabled
		#
		if ($CTX->{INPUT}{SUBSYSTEMS}{$key}{ENABLE} ne "YES" ) {
			next;
		}

		#
		# create the subsystems used OBJ_LIST
		#
		my @OBJ_LIST = ();
		foreach my $elem (@{$CTX->{INPUT}{SUBSYSTEMS}{$key}{INIT_OBJ_FILES}}) {
			push(@OBJ_LIST,$elem);
		}
		foreach my $elem (@{$CTX->{INPUT}{SUBSYSTEMS}{$key}{ADD_OBJ_FILES}}) {
			push(@OBJ_LIST,$elem);
		}

		#
		# create the subsystems used SUBSYSTEMS_LIST
		#
		my @SUBSYSTEMS_LIST = ();
		foreach my $elem (@{$CTX->{INPUT}{SUBSYSTEMS}{$key}{REQUIRED_SUBSYSTEMS}}) {
			push(@SUBSYSTEMS_LIST,$elem);
		}

		#
		# create the subsystems used LIBRARIES_LIST
		#
		my @LIBRARIES_LIST = ();
		foreach my $elem (@{$CTX->{INPUT}{SUBSYSTEMS}{$key}{REQUIRED_LIBRARIES}}) {
			push(@LIBRARIES_LIST,$elem);
		}

		#
		# now collect the info from the subsystems static modules
		#
		foreach my $subkey (sort keys %{$CTX->{INPUT}{MODULES}}) {
			#
			# we only want STATIC modules
			#
			if ($CTX->{INPUT}{MODULES}{$subkey}{BUILD} ne "STATIC") {
				next;
			}

			#
			# we only want modules which belong to the current subsystem
			#
			if ($CTX->{INPUT}{MODULES}{$subkey}{SUBSYSTEM} ne $name) {
				next;
			}

			#
			# add OBJ of static modules to the subsystems used OBJ_LIST
			#
			foreach my $elem (@{$CTX->{INPUT}{MODULES}{$subkey}{INIT_OBJ_FILES}}) {
				push(@OBJ_LIST,$elem);
			}
			foreach my $elem (@{$CTX->{INPUT}{MODULES}{$subkey}{ADD_OBJ_FILES}}) {
				push(@OBJ_LIST,$elem);
			}

			#
			# create the subsystems used SUBSYSTEMS_LIST
			#
			foreach my $elem (@{$CTX->{INPUT}{MODULES}{$subkey}{REQUIRED_SUBSYSTEMS}}) {
				push(@SUBSYSTEMS_LIST,$elem);
			}

			#
			# create the subsystems used LIBRARIES_LIST
			#
			foreach my $elem (@{$CTX->{INPUT}{MODULES}{$subkey}{REQUIRED_LIBRARIES}}) {
				push(@LIBRARIES_LIST,$elem);
			}
		}

		#
		# set the lists
		#
		@{$CTX->{DEPEND}{SUBSYSTEMS}{$key}{OBJ_LIST}} = @OBJ_LIST;
		@{$CTX->{DEPEND}{SUBSYSTEMS}{$key}{SUBSYSTEMS_LIST}} = @SUBSYSTEMS_LIST;
		@{$CTX->{DEPEND}{SUBSYSTEMS}{$key}{LIBRARIES_LIST}} = @LIBRARIES_LIST;
	}

	return;
}

###########################################################
# This function creates the dependencies for shared modules
# _do_depend_shared_modules($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
sub _do_depend_shared_modules($)
{
	my $CTX = shift;

	foreach my $key (sort keys %{$CTX->{INPUT}{MODULES}}) {
		my $name = $CTX->{OUTPUT}{MODULES}{$key}{NAME};

		if ($CTX->{INPUT}{MODULES}{$key}{BUILD} ne "SHARED" ) {
			next;
		}

	}

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

	$CTX->{OUTPUT}{PROTO} = ();
	@{$CTX->{OUTPUT}{PROTO}{OBJ_LIST}} = ();

	$CTX->{OUTPUT}{TARGETS}{ALL} = ();
	$CTX->{OUTPUT}{TARGETS}{ALL}{TARGET} = "all";
	@{$CTX->{OUTPUT}{TARGETS}{ALL}{DEPEND_LIST}} = ();

	_do_depend_subsystems($CTX);

	_do_depend_shared_modules($CTX);

	_do_depend_libraries($CTX);

	_do_depend_binaries($CTX);

	return;
}
