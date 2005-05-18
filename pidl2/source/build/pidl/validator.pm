###################################################
# check that a parsed IDL file is valid
# Copyright tridge@samba.org 2003
# released under the GNU GPL

package IdlValidator;
use Data::Dumper;

use strict;

#####################################################################
# signal a fatal validation error
sub fatal($$)
{
	my $pos = shift;
	my $s = shift;
	die("$pos->{FILE}:$pos->{LINE}:$s\n");
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

my %property_list = (
	# interface
	"helpstring"		=> {},
	"version"		=> {},
	"uuid"			=> {},
	"endpoint"		=> {},
	"pointer_default"	=> {},
	"pointer_default_top"	=> {},
	"depends"		=> {},
	"authservice"		=> {},

	# dcom
	"object"		=> {},
	"local"			=> {},
	"iid_is"		=> {},
	"call_as"		=> {},
	"iid_is"		=> {},
	"idempotent"		=> {},

	# function
	"id"			=> {},# what is that? --metze 
	"in"			=> {},
	"out"			=> {},

	# pointer
	"ref"			=> {},
	"ptr"			=> {},
	"unique"		=> {},
	"relative"		=> {},

	# ndr_size
	"gensize"		=> {},
	"value"			=> {},
	"flag"			=> {},

	# generic
	"public"		=> {},
	"nopush"		=> {},
	"nopull"		=> {},
	"noprint"		=> {},

	# union
	"switch_is"		=> {},
	"switch_type"		=> {},
	"nodiscriminant"	=> {},
	"case"			=> {},
	"default"		=> {},

	# subcontext
	"subcontext"		=> {},
	"subcontext_size"	=> {},
	"compression"		=> {},
	"obfuscation"		=> {},

	# enum
	"enum8bit"		=> {},
	"enum16bit"		=> {},
	"v1_enum"		=> {},

	# bitmap
	"bitmap8bit"		=> {},
	"bitmap16bit"		=> {},
	"bitmap32bit"		=> {},
	"bitmap64bit"		=> {},

	# array
	"range"			=> {},
	"size_is"		=> {},
	"length_is"		=> {},
);

#####################################################################
# check for unknown properties
sub ValidProperties($)
{
	my $e = shift;

	return unless defined $e->{PROPERTIES};

	foreach my $key (keys %{$e->{PROPERTIES}}) {
		if (not defined $property_list{$key}) {
			fatal($e, el_name($e) . ": unknown property '$key'\n");
		}
	}
}

#####################################################################
# parse a struct
sub ValidElement($)
{
	my $e = shift;

	ValidProperties($e);

	if (util::has_property($e, "ptr")) {
		fatal($e, el_name($e) . " : pidl does not support full NDR pointers yet\n");
	}

	# Check whether switches are used correctly.
	if (my $switch = util::has_property($e, "switch_is")) {
		my $e2 = util::find_sibling($e, $switch);
		my $type = typelist::getType($e->{TYPE});

		if (defined($type) and $type->{DATA}->{TYPE} ne "UNION") {
			fatal($e, el_name($e) . ": switch_is() used on non-union type $e->{TYPE} which is a $type->{DATA}->{TYPE}");
		}

		if (!util::has_property($type, "nodiscriminant") and defined($e2)) {
			my $discriminator_type = util::has_property($type, "switch_type");
			$discriminator_type = "uint32" unless defined ($discriminator_type);

			if ($e2->{TYPE} ne $discriminator_type) {
				print el_name($e) . ": Warning: switch_is() is of type $e2->{TYPE}, while discriminator type for union $type->{NAME} is $discriminator_type\n";
			}
		}
	}

	if (defined (util::has_property($e, "subcontext_size")) and not defined(util::has_property($e, "subcontext"))) {
		fatal($e, el_name($e) . " : subcontext_size() on non-subcontext element");
	}

	if (defined (util::has_property($e, "compression")) and not defined(util::has_property($e, "subcontext"))) {
		fatal($e, el_name($e) . " : compression() on non-subcontext element");
	}

	if (defined (util::has_property($e, "obfuscation")) and not defined(util::has_property($e, "subcontext"))) {
		fatal($e, el_name($e) . " : obfuscation() on non-subcontext element");
	}

	if (!$e->{POINTERS} && (
		util::has_property($e, "ptr") or
		util::has_property($e, "unique") or
		util::has_property($e, "relative") or
		util::has_property($e, "ref"))) {
		fatal($e, el_name($e) . " : pointer properties on non-pointer element\n");	
	}
}

#####################################################################
# parse a struct
sub ValidStruct($)
{
	my($struct) = shift;

	ValidProperties($struct);

	foreach my $e (@{$struct->{ELEMENTS}}) {
		$e->{PARENT} = $struct;
		ValidElement($e);
	}
}

#####################################################################
# parse a union
sub ValidUnion($)
{
	my($union) = shift;

	ValidProperties($union);

	if (util::has_property($union->{PARENT}, "nodiscriminant") and util::has_property($union->{PARENT}, "switch_type")) {
		fatal($union->{PARENT}, $union->{PARENT}->{NAME} . ": switch_type() on union without discriminant");
	}
	
	foreach my $e (@{$union->{ELEMENTS}}) {
		$e->{PARENT} = $union;

		if (defined($e->{PROPERTIES}->{default}) and 
			defined($e->{PROPERTIES}->{case})) {
			fatal $e, "Union member $e->{NAME} can not have both default and case properties!\n";
		}
		
		unless (defined ($e->{PROPERTIES}->{default}) or 
				defined ($e->{PROPERTIES}->{case})) {
			fatal $e, "Union member $e->{NAME} must have default or case property\n";
		}

		if (util::has_property($e, "ref")) {
			fatal($e, el_name($e) . " : embedded ref pointers are not supported yet\n");
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

	ValidProperties($typedef);

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

	ValidProperties($fn);

	foreach my $e (@{$fn->{ELEMENTS}}) {
		$e->{PARENT} = $fn;
		if (util::has_property($e, "ref") && !$e->{POINTERS}) {
			fatal $e, "[ref] variables must be pointers ($fn->{NAME}/$e->{NAME})\n";
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

	ValidProperties($interface);

	if (util::has_property($interface, "pointer_default") && 
		$interface->{PROPERTIES}->{pointer_default} eq "ptr") {
		fatal $interface, "Full pointers are not supported yet\n";
	}

	if (util::has_property($interface, "object")) {
     		if (util::has_property($interface, "version") && 
			$interface->{PROPERTIES}->{version} != 0) {
			fatal $interface, "Object interfaces must have version 0.0 ($interface->{NAME})\n";
		}

		if (!defined($interface->{BASE}) && 
			not ($interface->{NAME} eq "IUnknown")) {
			fatal $interface, "Object interfaces must all derive from IUnknown ($interface->{NAME})\n";
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
