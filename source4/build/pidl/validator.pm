###################################################
# check that a parsed IDL file is valid
# Copyright tridge@samba.org 2003
# released under the GNU GPL

package IdlValidator;

use strict;
use Data::Dumper;


#####################################################################
# signal a fatal validation error
sub fatal($)
{
	my $s = shift;
	print "$s\n";
	die "IDL is not valid\n";
}

#####################################################################
# parse a struct
sub ValidStruct($)
{
	my($struct) = shift;

	foreach my $e (@{$struct->{ELEMENTS}}) {

	}
}


#####################################################################
# parse a union
sub ValidUnion($)
{
	my($union) = shift;
	foreach my $e (@{$union->{DATA}}) {
	}
}

#####################################################################
# parse a typedef
sub ValidTypedef($)
{
	my($typedef) = shift;
	my $data = $typedef->{DATA};

	if (ref($data) eq "HASH") {
		if ($data->{TYPE} eq "STRUCT") {
			ValidStruct($data);
		}

		if ($data->{TYPE} eq "UNION") {
			ValidUnion($data);
		}
	}
}

#####################################################################
# parse a function
sub ValidFunction($)
{
	my($fn) = shift;

	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "ref") && !$e->{POINTERS}) {
			fatal "[ref] variables must be pointers ($fn->{NAME}/$e->{NAME})\n";
		}
	}
}

#####################################################################
# parse the interface definitions
sub ValidInterface($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};

	foreach my $d (@{$data}) {
		($d->{TYPE} eq "TYPEDEF") &&
		    ValidTypedef($d);
		($d->{TYPE} eq "FUNCTION") && 
		    ValidFunction($d);
	}

}

#####################################################################
# parse a parsed IDL into a C header
sub Validate($)
{
	my($idl) = shift;

	foreach my $x (@{$idl}) {
		($x->{TYPE} eq "INTERFACE") && 
		    ValidInterface($x);
	}
}

1;
