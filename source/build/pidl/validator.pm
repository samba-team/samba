###################################################
# check that a parsed IDL file is valid
# Copyright tridge@samba.org 2003
# released under the GNU GPL

package IdlValidator;
use Data::Dumper;

use strict;

#####################################################################
# signal a fatal validation error
sub fatal($)
{
	my $s = shift;
	print "$s\n";
	die "IDL is not valid\n";
}

sub el_name($)
{
	my $e = shift;

	if ($e->{PARENT} && $e->{PARENT}->{NAME}) {
		return "$e->{PARENT}->{NAME}.$e->{NAME}";
	}

	if ($e->{PARENT} && $e->{PARENT}->{PARENT}->{NAME}) {
		return "$e->{PARENT}->{PARENT}->{NAME}.$e->{NAME}";
	}

	if ($e->{PARENT}) {
		return "$e->{PARENT}->{NAME}.$e->{NAME}";
	}
	return $e->{NAME};
}

#####################################################################
# parse a struct
sub ValidElement($)
{
	my $e = shift;
	
	if (util::has_property($e, "ptr")) {
		fatal(el_name($e) . " : pidl does not support full NDR pointers yet\n");
	}

	if (util::has_property($e, "size_is") and not defined ($e->{ARRAY_LEN})) {
		fatal(el_name($e) . " : size_is() on non-array element");
	}

	if (util::has_property($e, "length_is") and not defined ($e->{ARRAY_LEN})) {
		fatal(el_name($e) . " : length_is() on non-array element");
	}

	
	if (!$e->{POINTERS} && (
		util::has_property($e, "ptr") or
		util::has_property($e, "unique") or
		util::has_property($e, "relative") or
		util::has_property($e, "ref"))) {
		fatal(el_name($e) . " : pointer properties on non-pointer element\n");	
	}
}

#####################################################################
# parse a struct
sub ValidStruct($)
{
	my($struct) = shift;

	foreach my $e (@{$struct->{ELEMENTS}}) {
		if (util::has_property($e, "ref")) {
			fatal(el_name($e) . " : embedded ref pointers are not supported yet\n");
		}
	
		$e->{PARENT} = $struct;
		ValidElement($e);
	}
}

#####################################################################
# parse a union
sub ValidUnion($)
{
	my($union) = shift;
	foreach my $e (@{$union->{ELEMENTS}}) {
		$e->{PARENT} = $union;

		if (defined($e->{PROPERTIES}->{default}) and 
			defined($e->{PROPERTIES}->{case})) {
			fatal "Union member $e->{NAME} can not have both default and case properties!\n";
		}
		
		unless (defined ($e->{PROPERTIES}->{default}) or 
				defined ($e->{PROPERTIES}->{case})) {
			fatal "Union member $e->{NAME} must have default or case property\n";
		}

		if (util::has_property($e, "ref")) {
			fatal(el_name($e) . " : embedded ref pointers are not supported yet\n");
		}


		ValidElement($e);
	}
}

#####################################################################
# parse a typedef
sub ValidTypedef($)
{
	my($typedef) = shift;
	my $data = $typedef->{DATA};

	$data->{PARENT} = $typedef;

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

	foreach my $e (@{$fn->{ELEMENTS}}) {
		$e->{PARENT} = $fn;
		if (util::has_property($e, "ref") && !$e->{POINTERS}) {
			fatal "[ref] variables must be pointers ($fn->{NAME}/$e->{NAME})\n";
		}
		ValidElement($e);
	}
}

#####################################################################
# parse the interface definitions
sub ValidInterface($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};

	if (util::has_property($interface, "pointer_default") && 
		$interface->{PROPERTIES}->{pointer_default} eq "ptr") {
		fatal "Full pointers are not supported yet\n";
	}

	if (util::has_property($interface, "object")) {
     	if(util::has_property($interface, "version") && 
			$interface->{PROPERTIES}->{version} != 0) {
			fatal "Object interfaces must have version 0.0 ($interface->{NAME})\n";
		}

		if(!defined($interface->{BASE}) && 
			not ($interface->{NAME} eq "IUnknown")) {
			fatal "Object interfaces must all derive from IUnknown ($interface->{NAME})\n";
		}
	}
		
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
