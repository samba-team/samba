###########################################################
### SMB Build System					###
### - the input checking functions			###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################


sub str2array($)
{
	my $str = shift;
	my @ar = ();

	$str =~ s/^[\t\n ]*//g;

	$str =~ s/[\t\n ]*$//g;

	$str =~ s/([\t\n ]+)/ /g;

	if (length($str)==0) {
		return ();
	}

	@ar = split(/[ \t\n]/,$str);

	return @ar;
}

sub _check_subsystems($)
{
	my $CTX = shift;

	foreach my $subsys (sort keys %{$CTX->{INPUT}{SUBSYSTEMS}}) {
		if ($CTX->{INPUT}{SUBSYSTEMS}{$subsys}{ENABLE} ne "YES") {
			printf("Subsystem: %s disabled!\n",$CTX->{INPUT}{SUBSYSTEMS}{$subsys}{NAME});
			next;
		}
	}

	return;
}

sub _check_modules($)
{
	my $CTX = shift;
	
	foreach my $mod (sort keys %{$CTX->{INPUT}{MODULES}}) {
		my $subsys = $CTX->{INPUT}{MODULES}{$mod}{SUBSYSTEM};
		my $default_build = $CTX->{INPUT}{MODULES}{$mod}{DEFAULT_BUILD};
		my $build = $CTX->{INPUT}{MODULES}{$mod}{CHOSEN_BUILD};
		my $use_default = 0;

		if (!(defined($CTX->{INPUT}{SUBSYSTEMS}{$subsys}))) {
			$CTX->{INPUT}{MODULES}{$mod}{BUILD} = "NOT";
			printf("Module: %s...PARENT SUBSYSTEM DISABLED\n",$mod);
			next;
		}

		if ($build eq "DEFAULT") {
			$build = $default_build;
			$use_default = 1;
		}

		if ($build eq "SHARED") {
			$CTX->{INPUT}{MODULES}{$mod}{BUILD} = "SHARED";
			printf("Module: %s...SHARED\n",$mod);
		} elsif ($build eq "STATIC") {
			$CTX->{INPUT}{MODULES}{$mod}{BUILD} = "STATIC";
			printf("Module: %s...STATIC\n",$mod);
		} else {
			$CTX->{INPUT}{MODULES}{$mod}{BUILD} = "NOT";
			printf("Module: %s...NOT\n",$mod);
			next;
		}
	}

	return;
}

sub _check_libraries($)
{
	my $CTX = shift;

	foreach my $lib (sort keys %{$CTX->{INPUT}{LIBRARIES}}) {
		if ($CTX->{INPUT}{LIBRARIES}{$lib}{ENABLE} ne "YES") {
			printf("Library: %s disabled!\n",$CTX->{INPUT}{LIBRARIES}{$lib}{NAME});
			next;
		}
	}

	return;
}

sub _check_binaries($)
{
	my $CTX = shift;

	foreach my $bin (sort keys %{$CTX->{INPUT}{BINARIES}}) {
		if ($CTX->{INPUT}{BINARIES}{$bin}{ENABLE} ne "YES") {
			printf("Binary: %s disabled!\n",$CTX->{INPUT}{BINARIES}{$bin}{NAME});
			next;
		}
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
