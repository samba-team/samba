###########################################################
### SMB Build System					###
### - the dependency calculation functions		###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################

###########################################################
# This function creates the dependency tree from the SMB_BUILD 
# context
# create_depend_output($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
sub create_depend_output($)
{
	my $CTX = shift;

	$CTX->{INFO} = ();

	$CTX->{OUTPUT} = ();

	return;
}
