###########################################################
### SMB Build System					###
### - the input checking functions			###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################


sub _split($)
{
	my $str = shift;

	if (length($str)==0) {
		return ();
	}

	return split(/[ \t\n]/,$str);
}

sub _check_subsystems($)
{
	my $CTX = shift;

	foreach my $subsys (sort keys %{$CTX->{RAW_INPUT}{SUBSYSTEMS}}) {
		if ($CTX->{RAW_INPUT}{SUBSYSTEMS}{$subsys}{ENABLE} ne "YES") {
			printf("Subsystem: %s disabled!\n",$CTX->{RAW_INPUT}{SUBSYSTEMS}{$subsys}{NAME});
			next;
		}

		$CTX->{INPUT}{SUBSYSTEMS}{$subsys}{NAME} = $subsys;
		$CTX->{INPUT}{SUBSYSTEMS}{$subsys}{INIT_OBJ_FILE} = _split($CTX->{RAW_INPUT}{SUBSYSTEMS}{$subsys}{INIT_OBJ_FILE});
		$CTX->{INPUT}{SUBSYSTEMS}{$subsys}{ADD_OBJ_FILES} = _split($CTX->{RAW_INPUT}{SUBSYSTEMS}{$subsys}{ADD_OBJ_FILES});
		$CTX->{INPUT}{SUBSYSTEMS}{$subsys}{REQUIRED_LIBS} = _split($CTX->{RAW_INPUT}{SUBSYSTEMS}{$subsys}{REQUIRED_LIBS});
		$CTX->{INPUT}{SUBSYSTEMS}{$subsys}{REQUIRED_SUBSYSTEMS} = _split($CTX->{RAW_INPUT}{SUBSYSTEMS}{$subsys}{REQUIRED_SUBSYSTEMS});

	}

	return;
}

sub _check_modules($)
{
	my $CTX = shift;
	
	foreach my $mod (sort keys %{$CTX->{RAW_INPUT}{MODULES}}) {
		my $subsys = $CTX->{RAW_INPUT}{MODULES}{$mod}{SUBSYSTEM};
		my $default_build = $CTX->{RAW_INPUT}{MODULES}{$mod}{DEFAULT_BUILD};
		my $chosen_build = $CTX->{RAW_INPUT}{MODULES}{$mod}{CHOSEN_BUILD};
		my $build = "";

		if (!(defined($CTX->{INPUT}{SUBSYSTEMS}{$subsys}))) {
			printf("Module: %s...PARENT SUBSYSTEM DISABLED\n",$mod);
			next;
		}

		if ($chosen_build eq "DEFAULT") {
			if ($default_build eq "SHARED") {
				printf("Module: %s...SHARED\n",$mod);
			} elsif ($default_build eq "STATIC") {
				printf("Module: %s...STATIC\n",$mod);
			} else {
				printf("Module: %s...NOT\n",$mod);
				next;
			}
		}

		$CTX->{INPUT}{MODULES}{$mod}{NAME} = $mod;
		$CTX->{INPUT}{MODULES}{$mod}{SUBSYSTEM} = \$CTX->{INPUT}{SUBSYSTEMS}{$subsys};
		$CTX->{INPUT}{MODULES}{$mod}{BUILD} = $build;
		$CTX->{INPUT}{MODULES}{$mod}{INIT_OBJ_FILE} = _split($CTX->{RAW_INPUT}{MODULES}{$mod}{INIT_OBJ_FILE});
		$CTX->{INPUT}{MODULES}{$mod}{ADD_OBJ_FILES} = _split($CTX->{RAW_INPUT}{MODULES}{$mod}{ADD_OBJ_FILES});
		$CTX->{INPUT}{MODULES}{$mod}{REQUIRED_LIBS} = _split($CTX->{RAW_INPUT}{MODULES}{$mod}{REQUIRED_LIBS});
		$CTX->{INPUT}{MODULES}{$mod}{REQUIRED_SUBSYSTEMS} = _split($CTX->{RAW_INPUT}{MODULES}{$mod}{REQUIRED_SUBSYSTEMS});
	}

	return;
}

sub _check_libraries($)
{
	my $CTX = shift;

	foreach my $lib (sort keys %{$CTX->{RAW_INPUT}{LIBRARIES}}) {
		if ($CTX->{RAW_INPUT}{LIBRARIES}{$lib}{ENABLE} ne "YES") {
			printf("Library: %s disabled!\n",$CTX->{RAW_INPUT}{LIBRARIES}{$lib}{NAME});
			next;
		}

		$CTX->{INPUT}{LIBRARIES}{$lib}{NAME} = $lib;
		$CTX->{INPUT}{LIBRARIES}{$lib}{OBJ_FILES} = _split($CTX->{RAW_INPUT}{LIBRARIES}{$lib}{OBJ_FILES});
		$CTX->{INPUT}{LIBRARIES}{$lib}{REQUIRED_LIBS} = _split($CTX->{RAW_INPUT}{LIBRARIES}{$lib}{REQUIRED_LIBS});
		$CTX->{INPUT}{LIBRARIES}{$lib}{REQUIRED_SUBSYSTEMS} = _split($CTX->{RAW_INPUT}{LIBRARIES}{$lib}{REQUIRED_SUBSYSTEMS});

	}

	return;
}

sub _check_binaries($)
{
	my $CTX = shift;

	foreach my $bin (sort keys %{$CTX->{RAW_INPUT}{BINARIES}}) {
		if ($CTX->{RAW_INPUT}{BINARIES}{$bin}{ENABLE} ne "YES") {
			printf("Binary: %s disabled!\n",$CTX->{RAW_INPUT}{BINARIES}{$bin}{NAME});
			next;
		}

		$CTX->{INPUT}{BINARIES}{$bin}{NAME} = $bin;
		$CTX->{INPUT}{BINARIES}{$bin}{BUILD_TARGETS} = _split($CTX->{RAW_INPUT}{BINARIES}{$bin}{BUILD_TARGETS});
		$CTX->{INPUT}{BINARIES}{$bin}{INSTALL_PATH} = _split($CTX->{RAW_INPUT}{BINARIES}{$bin}{INSTALL_PATH});
		$CTX->{INPUT}{BINARIES}{$bin}{OBJ_FILES} = _split($CTX->{RAW_INPUT}{BINARIES}{$bin}{OBJ_FILES});
		$CTX->{INPUT}{BINARIES}{$bin}{REQUIRED_LIBS} = _split($CTX->{RAW_INPUT}{BINARIES}{$bin}{REQUIRED_LIBS});
		$CTX->{INPUT}{BINARIES}{$bin}{REQUIRED_SUBSYSTEMS} = _split($CTX->{RAW_INPUT}{BINARIES}{$bin}{REQUIRED_SUBSYSTEMS});

	}

	return;
}

###########################################################
# This function checks the input from the configure script 
#
# check_input($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
sub check_input($)
{
	my $CTX = shift;

	_check_subsystems($CTX);

	_check_modules($CTX);

	_check_libraries($CTX);

	_check_binaries($CTX);

	return;
}
