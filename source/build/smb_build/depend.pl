###########################################################
### SMB Build System					###
### - the dependency calculation functions		###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################

###########################################################
# This function resolves the dependencies 
# for the SUBSYSTEMS_LIST
# @SUBSYSTEMS_LIST = _do_calc_subsystem_list($SMB_BUILD_CTX, \@SUBSYSTEMS_LIST);
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
#
# \@SUBSYSTEMS_LIST -	the reference to the SUBSYSTEMS_LIST
#
# @SUBSYSTEMS_LIST -	the expanded resulting SUBSYSTEMS_LIST
#
sub _do_calc_subsystem_list($$)
{
	my $CTX = shift;
	my $subsys_list = shift;
	my @SUBSYSTEMS_LIST = @$subsys_list;

	#
	# now try to resolve the dependencies for the library
	#
	my $i = 0;
	my $count = $#SUBSYSTEMS_LIST;
	for (;$i<=$count;$i++) {			
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

	return @SUBSYSTEMS_LIST;
}

###########################################################
# This function resolves the dependencies 
# for the LIBRARIES_LIST based on the SUBSYSTEMS_LIST
# @LIBRARIES_LIST = _do_calc_libraries_list($SMB_BUILD_CTX, \@SUBSYSTEMS_LIST, \@LIBRARIES_LIST);
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
#
# \@SUBSYSTEMS_LIST -	the reference to the SUBSYSTEMS_LIST
#
# \@LIBRARIES_LIST -	the reference to the LIBRARIES_LIST
#
# @LIBRARIES_LIST -	the expanded resulting LIBRARIES_LIST
#
sub _do_calc_libraries_list($$$)
{
	my $CTX = shift;
	my $subsys_list = shift;
	my @SUBSYSTEMS_LIST = @$subsys_list;
	my $libs_list = shift;
	my @LIBRARIES_LIST = @$libs_list;

	#
	# add the LIBARARIES of each subsysetm in the @SUBSYSTEMS_LIST
	#
	foreach my $elem (@SUBSYSTEMS_LIST) {			
		#
		# see if the subsystem depends on a not listed LIBRARY
		#
		foreach my $elem1 (@{$CTX->{DEPEND}{SUBSYSTEMS}{$elem}{LIBRARIES_LIST}}) {
			my $seen = 0;
			#
			# check if it's already in the list
			#
			foreach my $elem2 (@LIBRARIES_LIST) {
				#
				# check of the names matche
				#
				if ($elem1 eq $elem2) {
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
			push(@LIBRARIES_LIST,$elem1);
		}
	}

	return @LIBRARIES_LIST;
}

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
		my @STATIC_MODULES_LIST = ();
		my @INIT_FUNCTIONS = ();

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
		push (@OBJ_LIST, @{$CTX->{INPUT}{SUBSYSTEMS}{$key}{INIT_OBJ_FILES}});
		push (@OBJ_LIST, @{$CTX->{INPUT}{SUBSYSTEMS}{$key}{ADD_OBJ_FILES}});

		#
		# create the subsystems used SUBSYSTEMS_LIST
		#
		my @SUBSYSTEMS_LIST = ();
		push (@SUBSYSTEMS_LIST, (@{$CTX->{INPUT}{SUBSYSTEMS}{$key}{REQUIRED_SUBSYSTEMS}}));
		#
		# create the subsystems used LIBRARIES_LIST
		#
		my @LIBRARIES_LIST = ();
		push (@LIBRARIES_LIST, @{$CTX->{INPUT}{SUBSYSTEMS}{$key}{REQUIRED_LIBRARIES}});

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
			# add it to the STATIC_MODULES_LIST
			#
			push(@STATIC_MODULES_LIST,$subkey);
			push (@INIT_FUNCTIONS, $CTX->{INPUT}{MODULES}{$subkey}{INIT_FUNCTION}) if $CTX->{INPUT}{MODULES}{$subkey}{INIT_FUNCTION} ne "";

			#
			# add OBJS of static modules to the subsystems used OBJ_LIST
			#
			push (@OBJ_LIST, (@{$CTX->{INPUT}{MODULES}{$subkey}{INIT_OBJ_FILES}}));
			push (@OBJ_LIST, (@{$CTX->{INPUT}{MODULES}{$subkey}{ADD_OBJ_FILES}}));

			#
			# add SUBSYSTEMS of static modules to the subsystems used SUBSYSTEMS_LIST
			#
			push (@SUBSYSTEMS_LIST, (@{$CTX->{INPUT}{MODULES}{$subkey}{REQUIRED_SUBSYSTEMS}}));

			#
			# add LIBRARIES of static modules to  the subsystems used LIBRARIES_LIST
			#
			push (@LIBRARIES_LIST, (@{$CTX->{INPUT}{MODULES}{$subkey}{REQUIRED_LIBRARIES}}));
		}

		#
		# set the lists
		#
		@{$CTX->{DEPEND}{SUBSYSTEMS}{$key}{INIT_FUNCTIONS}} = @INIT_FUNCTIONS;
		@{$CTX->{DEPEND}{SUBSYSTEMS}{$key}{OBJ_LIST}} = @OBJ_LIST;
		@{$CTX->{DEPEND}{SUBSYSTEMS}{$key}{STATIC_MODULES_LIST}} = @STATIC_MODULES_LIST;
		@{$CTX->{DEPEND}{SUBSYSTEMS}{$key}{SUBSYSTEMS_LIST}} = @SUBSYSTEMS_LIST;
		@{$CTX->{DEPEND}{SUBSYSTEMS}{$key}{LIBRARIES_LIST}} = @LIBRARIES_LIST;
	}

	return;
}

###########################################################
# This function creates the dependencies for ext libs
# _do_depend_ext_libs($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
sub _do_depend_ext_libs($)
{
	my $CTX = shift;

	#
	# loop over all ext libs
	#
	foreach my $key (sort keys %{$CTX->{INPUT}{EXT_LIBS}}) {
		my $name = $CTX->{INPUT}{EXT_LIBS}{$key}{NAME};

		#
		# if it's not a shared module skip it
		#
		if ($CTX->{INPUT}{EXT_LIBS}{$key}{ENABLE} ne "YES") {
			next;
		}

		#
		# set the lists
		#
		$CTX->{DEPEND}{EXT_LIBS}{$key}{NAME} = $name;
		@{$CTX->{DEPEND}{EXT_LIBS}{$key}{LIBS}} = @{$CTX->{INPUT}{EXT_LIBS}{$key}{LIBS}};
		@{$CTX->{DEPEND}{EXT_LIBS}{$key}{CFLAGS}} = @{$CTX->{INPUT}{EXT_LIBS}{$key}{CFLAGS}};
		@{$CTX->{DEPEND}{EXT_LIBS}{$key}{CPPFLAGS}} = @{$CTX->{INPUT}{EXT_LIBS}{$key}{CPPFLAGS}};
		@{$CTX->{DEPEND}{EXT_LIBS}{$key}{LDFLAGS}} = @{$CTX->{INPUT}{EXT_LIBS}{$key}{LDFLAGS}};
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
		push (@SUBSYSTEMS_LIST, (@{$CTX->{INPUT}{MODULES}{$key}{REQUIRED_SUBSYSTEMS}}));

		#
		# now try to resolve the dependencies for the shared module
		#
		@SUBSYSTEMS_LIST = _do_calc_subsystem_list($CTX, \@SUBSYSTEMS_LIST);

		#
		# create the shared modules used LIBRARIES_LIST
		#
		my @LIBRARIES_LIST = ();
		push (@LIBRARIES_LIST, @{$CTX->{INPUT}{MODULES}{$key}{REQUIRED_LIBRARIES}});

		#
		# add the LIBARARIES of each subsysetm in the @SUBSYSTEMS_LIST
		#
		@LIBRARIES_LIST = _do_calc_libraries_list($CTX, \@SUBSYSTEMS_LIST, \@LIBRARIES_LIST);

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

		#
		# if it's not a library skip it
		#
		if ($CTX->{INPUT}{LIBRARIES}{$key}{ENABLE} ne "YES" ) {
			next;
		}

		#
		# create the libraries used SUBSYSTEMS_LIST
		#
		my @SUBSYSTEMS_LIST = ();
		push (@SUBSYSTEMS_LIST, @{$CTX->{INPUT}{LIBRARIES}{$key}{REQUIRED_SUBSYSTEMS}});

		#
		# now try to resolve the dependencies for the library
		#
		@SUBSYSTEMS_LIST = _do_calc_subsystem_list($CTX, \@SUBSYSTEMS_LIST);

		#
		# create the libraries used LIBRARIES_LIST
		#
		my @LIBRARIES_LIST = ();
		push (@LIBRARIES_LIST, @{$CTX->{INPUT}{LIBRARIES}{$key}{REQUIRED_LIBRARIES}});

		#
		# add the LIBARARIES of each subsysetm in the @SUBSYSTEMS_LIST
		#
		@LIBRARIES_LIST = _do_calc_libraries_list($CTX, \@SUBSYSTEMS_LIST, \@LIBRARIES_LIST);

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
		push (@SUBSYSTEMS_LIST, @{$CTX->{INPUT}{BINARIES}{$key}{REQUIRED_SUBSYSTEMS}});

		#
		# now try to resolve the dependencies for the binary
		#
		@SUBSYSTEMS_LIST = _do_calc_subsystem_list($CTX, \@SUBSYSTEMS_LIST);

		my @INIT_FUNCTIONS = ();

		foreach my $subkey (@SUBSYSTEMS_LIST)
		{
			push (@INIT_FUNCTIONS, $CTX->{INPUT}{SUBSYSTEMS}{$subkey}{INIT_FUNCTION}) if $CTX->{INPUT}{SUBSYSTEMS}{$subkey}{INIT_FUNCTION} ne "";
			
		}

		#
		# create the binaries used LIBRARIES_LIST
		#
		my @LIBRARIES_LIST = ();
		push (@LIBRARIES_LIST, @{$CTX->{INPUT}{BINARIES}{$key}{REQUIRED_LIBRARIES}});

		#
		# add the LIBARARIES of each subsysetm in the @SUBSYSTEMS_LIST
		#
		@LIBRARIES_LIST = _do_calc_libraries_list($CTX, \@SUBSYSTEMS_LIST, \@LIBRARIES_LIST);

		#
		# set the lists
		#
		@{$CTX->{DEPEND}{BINARIES}{$key}{SUBSYSTEMS_LIST}} = @SUBSYSTEMS_LIST;
		@{$CTX->{DEPEND}{BINARIES}{$key}{LIBRARIES_LIST}} = @LIBRARIES_LIST;
		@{$CTX->{DEPEND}{BINARIES}{$key}{INIT_FUNCTIONS}} = @INIT_FUNCTIONS;
	}

	return;
}

###########################################################
# This function creates the dependency tree from the SMB_BUILD 
# context
# create_depend($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
sub create_depend($)
{
	my $CTX = shift;

	_do_depend_ext_libs($CTX);

	_do_depend_subsystems($CTX);

	_do_depend_shared_modules($CTX);

	_do_depend_libraries($CTX);

	_do_depend_binaries($CTX);

	return;
}
