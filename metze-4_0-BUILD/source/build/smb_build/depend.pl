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

	return;
}
