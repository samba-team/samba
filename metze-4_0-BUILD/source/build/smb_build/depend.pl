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
			# add OBJS of static modules to the subsystems used OBJ_LIST
			#
			foreach my $elem (@{$CTX->{INPUT}{MODULES}{$subkey}{INIT_OBJ_FILES}}) {
				push(@OBJ_LIST,$elem);
			}
			foreach my $elem (@{$CTX->{INPUT}{MODULES}{$subkey}{ADD_OBJ_FILES}}) {
				push(@OBJ_LIST,$elem);
			}

			#
			# add SUBSYSTEMS of static modules to the subsystems used SUBSYSTEMS_LIST
			#
			foreach my $elem (@{$CTX->{INPUT}{MODULES}{$subkey}{REQUIRED_SUBSYSTEMS}}) {
				push(@SUBSYSTEMS_LIST,$elem);
			}

			#
			# add LIBRARIES of static modules to  the subsystems used LIBRARIES_LIST
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

	#
	# loop over all shared modules
	#
	foreach my $key (sort keys %{$CTX->{INPUT}{MODULES}}) {
		my $name = $CTX->{INPUT}{MODULES}{$key}{NAME};
		my $i = 0;
		my $count = 0;

		#
		# if it's not a shared module skip it
		#
		if ($CTX->{INPUT}{MODULES}{$key}{BUILD} ne "SHARED" ) {
			next;
		}

		#
		# create the shared modules used SUBSYSTEMS_LIST
		#
		my @SUBSYSTEMS_LIST = ();
		foreach my $elem (@{$CTX->{INPUT}{MODULES}{$key}{REQUIRED_SUBSYSTEMS}}) {
			push(@SUBSYSTEMS_LIST,$elem);
		}

		#
		# now try to resolve the dependencies for the shared module
		#
		$i = 0;
		$count = $#SUBSYSTEMS_LIST;
		for (;$i<$count;$i++) {			
			#
			# see if the current subsystem depends on other not listed subsystems
			#
			foreach my $elem (@{$CTX->{DEPEND}{SUBSYSTEMS}{$SUBSYSTEMS_LIST[$i]}{SUBSYSTEMS_LIST}}) {
				my $seen = 0;
				#
				# check if it's already in the list
				#
				foreach my $elem2 (@SUBSYSTEMS_LIST) {
					#
					# check of the names matche
					#
					if ($elem eq $elem2) {
						#
						# mark it as already in the list
						#
						$seen = 1;
						last;
					}
				}

				#
				# if it's already there skip it
				#
				if ($seen == 1) {
					next;
				}

				#
				# if it's not there add it
				# and $count++
				#
				push(@SUBSYSTEMS_LIST,$elem);
				$count++;
			}
		}

		#
		# create the shared modules used LIBRARIES_LIST
		#
		my @LIBRARIES_LIST = ();
		foreach my $elem (@{$CTX->{INPUT}{MODULES}{$key}{REQUIRED_LIBRARIES}}) {
			push(@LIBRARIES_LIST,$elem);
		}

		#
		# add the LIBARARIES of each subsysetm in the @SUBSYSTEMS_LIST
		#
		foreach my $elem (@SUBSYSTEMS_LIST) {			
			#
			# see if the subsystem depends on a not listed LIBRARY
			#
			foreach my $elem (@{$CTX->{DEPEND}{SUBSYSTEMS}{$SUBSYSTEMS_LIST[$i]}{LIBRARIES_LIST}}) {
				my $seen = 0;
				#
				# check if it's already in the list
				#
				foreach my $elem2 (@LIBRARIES_LIST) {
					#
					# check of the names matche
					#
					if ($elem eq $elem2) {
						#
						# mark it as already in the list
						#
						$seen = 1;
						last;
					}
				}

				#
				# if it's already there skip it
				#
				if ($seen == 1) {
					next;
				}

				#
				# if it's not there add it
				#
				push(@LIBRARIES_LIST,$elem);
			}
		}

		#
		# set the lists
		#
		@{$CTX->{DEPEND}{SHARED_MODULES}{$key}{SUBSYSTEMS_LIST}} = @SUBSYSTEMS_LIST;
		@{$CTX->{DEPEND}{SHARED_MODULES}{$key}{LIBRARIES_LIST}} = @LIBRARIES_LIST;
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

	#
	# loop over all libraries
	#
	foreach my $key (sort keys %{$CTX->{INPUT}{LIBRARIES}}) {
		my $name = $CTX->{INPUT}{LIBRARIES}{$key}{NAME};
		my $i = 0;
		my $count = 0;

		#
		# if it's not a library skip it
		#
		if ($CTX->{INPUT}{LIBRARIES}{$key}{BUILD} ne "SHARED" ) {
			next;
		}

		#
		# create the libraries used SUBSYSTEMS_LIST
		#
		my @SUBSYSTEMS_LIST = ();
		foreach my $elem (@{$CTX->{INPUT}{LIBRARIES}{$key}{REQUIRED_SUBSYSTEMS}}) {
			push(@SUBSYSTEMS_LIST,$elem);
		}

		#
		# now try to resolve the dependencies for the library
		#
		$i = 0;
		$count = $#SUBSYSTEMS_LIST;
		for (;$i<$count;$i++) {			
			#
			# see if the current subsystem depends on other not listed subsystems
			#
			foreach my $elem (@{$CTX->{DEPEND}{SUBSYSTEMS}{$SUBSYSTEMS_LIST[$i]}{SUBSYSTEMS_LIST}}) {
				my $seen = 0;
				#
				# check if it's already in the list
				#
				foreach my $elem2 (@SUBSYSTEMS_LIST) {
					#
					# check of the names matche
					#
					if ($elem eq $elem2) {
						#
						# mark it as already in the list
						#
						$seen = 1;
						last;
					}
				}

				#
				# if it's already there skip it
				#
				if ($seen == 1) {
					next;
				}

				#
				# if it's not there add it
				# and $count++
				#
				push(@SUBSYSTEMS_LIST,$elem);
				$count++;
			}
		}

		#
		# create the libraries used LIBRARIES_LIST
		#
		my @LIBRARIES_LIST = ();
		foreach my $elem (@{$CTX->{INPUT}{LIBRARIES}{$key}{REQUIRED_LIBRARIES}}) {
			push(@LIBRARIES_LIST,$elem);
		}

		#
		# add the LIBARARIES of each subsysetm in the @SUBSYSTEMS_LIST
		#
		foreach my $elem (@SUBSYSTEMS_LIST) {			
			#
			# see if the subsystem depends on a not listed LIBRARY
			#
			foreach my $elem (@{$CTX->{DEPEND}{SUBSYSTEMS}{$SUBSYSTEMS_LIST[$i]}{LIBRARIES_LIST}}) {
				my $seen = 0;
				#
				# check if it's already in the list
				#
				foreach my $elem2 (@LIBRARIES_LIST) {
					#
					# check of the names matche
					#
					if ($elem eq $elem2) {
						#
						# mark it as already in the list
						#
						$seen = 1;
						last;
					}
				}

				#
				# if it's already there skip it
				#
				if ($seen == 1) {
					next;
				}

				#
				# if it's not there add it
				#
				push(@LIBRARIES_LIST,$elem);
			}
		}

		#
		# set the lists
		#
		@{$CTX->{DEPEND}{LIBRARIES}{$key}{SUBSYSTEMS_LIST}} = @SUBSYSTEMS_LIST;
		@{$CTX->{DEPEND}{LIBRARIES}{$key}{LIBRARIES_LIST}} = @LIBRARIES_LIST;
	}

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

	#
	# loop over all binaries
	#
	foreach my $key (sort keys %{$CTX->{INPUT}{BINARIES}}) {
		my $name = $CTX->{INPUT}{BINARIES}{$key}{NAME};
		my $i = 0;
		my $count = 0;

		#
		# skip when the binary was disabled
		#
		if ($CTX->{INPUT}{BINARIES}{$key}{ENABLE} ne "YES" ) {
			next;
		}

		#
		# create the binaries used SUBSYSTEMS_LIST
		#
		my @SUBSYSTEMS_LIST = ();
		foreach my $elem (@{$CTX->{INPUT}{BINARIES}{$key}{REQUIRED_SUBSYSTEMS}}) {
			push(@SUBSYSTEMS_LIST,$elem);
		}

		#
		# now try to resolve the dependencies for the binary
		#
		$i = 0;
		$count = $#SUBSYSTEMS_LIST;
		for (;$i<$count;$i++) {			
			#
			# see if the current subsystem depends on other not listed subsystems
			#
			foreach my $elem (@{$CTX->{DEPEND}{SUBSYSTEMS}{$SUBSYSTEMS_LIST[$i]}{SUBSYSTEMS_LIST}}) {
				my $seen = 0;
				#
				# check if it's already in the list
				#
				foreach my $elem2 (@SUBSYSTEMS_LIST) {
					#
					# check of the names matche
					#
					if ($elem eq $elem2) {
						#
						# mark it as already in the list
						#
						$seen = 1;
						last;
					}
				}

				#
				# if it's already there skip it
				#
				if ($seen == 1) {
					next;
				}

				#
				# if it's not there add it
				# and $count++
				#
				push(@SUBSYSTEMS_LIST,$elem);
				$count++;
			}
		}

		#
		# create the binaries used LIBRARIES_LIST
		#
		my @LIBRARIES_LIST = ();
		foreach my $elem (@{$CTX->{INPUT}{BINARIES}{$key}{REQUIRED_LIBRARIES}}) {
			push(@LIBRARIES_LIST,$elem);
		}

		#
		# add the LIBARARIES of each subsysetm in the @SUBSYSTEMS_LIST
		#
		foreach my $elem (@SUBSYSTEMS_LIST) {			
			#
			# see if the subsystem depends on a not listed LIBRARY
			#
			foreach my $elem (@{$CTX->{DEPEND}{SUBSYSTEMS}{$SUBSYSTEMS_LIST[$i]}{LIBRARIES_LIST}}) {
				my $seen = 0;
				#
				# check if it's already in the list
				#
				foreach my $elem2 (@LIBRARIES_LIST) {
					#
					# check of the names matche
					#
					if ($elem eq $elem2) {
						#
						# mark it as already in the list
						#
						$seen = 1;
						last;
					}
				}

				#
				# if it's already there skip it
				#
				if ($seen == 1) {
					next;
				}

				#
				# if it's not there add it
				#
				push(@LIBRARIES_LIST,$elem);
			}
		}

		#
		# set the lists
		#
		@{$CTX->{DEPEND}{BINARIES}{$key}{SUBSYSTEMS_LIST}} = @SUBSYSTEMS_LIST;
		@{$CTX->{DEPEND}{BINARIES}{$key}{LIBRARIES_LIST}} = @LIBRARIES_LIST;
	}

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
