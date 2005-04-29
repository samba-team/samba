###################################################
# Samba4 NDR info tree generator
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# Copyright jelmer@samba.org 2004-2005
# released under the GNU GPL

package Ndr;

use strict;
use typelist;

#####################################################################
# return a table describing the order in which the parts of an element
# should be parsed
# Possible level types:
#  - POINTER
#  - ARRAY
#  - SUBCONTEXT
#  - SWITCH
#  - DATA
sub GetElementLevelTable($)
{
	my $e = shift;

	return ($e->{NDR_ORDER_TABLE}) if (defined $e->{NDR_ORDER_TABLE});

	my $order = [];
	my $is_deferred = 0;
	
	# FIXME: Process {ARRAY_SIZE} kinds of arrays

	# First, all the pointers
	foreach my $i (1..need_wire_pointer($e)) {
		push (@$order, { 
			TYPE => "POINTER",
			# for now, there can only be one pointer type per element
			POINTER_TYPE => pointer_type($e),
			IS_DEFERRED => "$is_deferred"
		});
		# everything that follows will be deferred
		$is_deferred = 1;
		# FIXME: Process array here possibly (in case of multi-dimensional arrays, etc)
	}

	if (defined($e->{ARRAY_LEN})) {
		push (@$order, {
			TYPE => "ARRAY",
			ARRAY_TYPE => array_type($e),
			SIZE_IS => util::has_property($e, "size_is"),
			LENGTH_IS => util::has_property($e, "length_is"),
			IS_DEFERRED => "$is_deferred"
		});
	}

	if (my $sub_size = util::has_property($e, "subcontext")) {
		push (@$order, {
			TYPE => "SUBCONTEXT",
			SUBCONTEXT_SIZE => $sub_size,
			IS_DEFERRED => $is_deferred,
			COMPRESSION => util::has_property($e, "compression")
		});
	}

	if (my $switch = util::has_property($e, "switch_is")) {
		push (@$order, {
			TYPE => "SWITCH", 
			SWITCH_IS => $switch,
			IS_DEFERRED => $is_deferred
		});
	}

	push (@$order, {
		TYPE => "DATA",
		DATA_TYPE => $e->{TYPE},
		NAME => $e->{NAME},
		IS_DEFERRED => $is_deferred,
		CONTAINS_DEFERRED => can_contain_deferred($e)
	});

	$e->{NDR_ORDER_TABLE} = $order;

	return $order;
}

#####################################################################
# see if a type contains any deferred data 
sub can_contain_deferred
{
	my $e = shift;

	return 1 if ($e->{POINTERS});
	return 0 if (is_scalar_type($e->{TYPE}));
	return 0 if (util::has_property($e, "subcontext"));
	return 1 unless (typelist::hasType($e->{TYPE})); # assume the worst

	my $type = typelist::getType($e->{TYPE});

	foreach my $x (@{$type->{DATA}->{ELEMENTS}}) {
		return 1 if (can_contain_deferred ($x));
	}
	
	return 0;
}

sub is_scalar_type($)
{
    my $type = shift;

	return 0 unless typelist::hasType($type);

	if (my $dt = typelist::getType($type)->{DATA}->{TYPE}) {
		return 1 if ($dt eq "SCALAR" or $dt eq "ENUM" or $dt eq "BITMAP");
	}

    return 0;
}

sub pointer_type($)
{
	my $e = shift;

	return undef unless $e->{POINTERS};
	
	return "ref" if (util::has_property($e, "ref"));
	return "ptr" if (util::has_property($e, "ptr"));
	return "unique" if (util::has_property($e, "unique"));
	return "relative" if (util::has_property($e, "relative"));
	return "ignore" if (util::has_property($e, "ignore"));

	return undef;
}

# return 1 if this is a fixed array
sub is_fixed_array($)
{
	my $e = shift;
	my $len = $e->{"ARRAY_LEN"};
	return 1 if (defined $len && util::is_constant($len));
	return 0;
}

# return 1 if this is a conformant array
sub is_conformant_array($)
{
	my $e = shift;
	return 1 if (util::has_property($e, "size_is"));
	return 0;
}

# return 1 if this is a inline array
sub is_inline_array($)
{
	my $e = shift;
	my $len = $e->{"ARRAY_LEN"};
	if (is_fixed_array($e) ||
	    defined $len && $len ne "*") {
		return 1;
	}
	return 0;
}

# return 1 if this is a varying array
sub is_varying_array($)
{
	my $e = shift;
	return util::has_property($e, "length_is");
}

# return 1 if this is a surrounding array (sometimes 
# referred to as an embedded array). Can only occur as 
# the last element in a struct and can not contain any pointers.
sub is_surrounding_array($)
{
	my $e = shift;

	return ($e->{POINTERS} == 0 
		and defined $e->{ARRAY_LEN} 
		and	$e->{ARRAY_LEN} eq "*"
		and $e == $e->{PARENT}->{ELEMENTS}[-1] 
		and $e->{PARENT}->{TYPE} ne "FUNCTION");
}

sub array_type($)
{
	my $e = shift;

	return "conformant-varying" if (is_varying_array($e) and is_conformant_array($e));
	return "conformant" if (is_varying_array($e));
	return "varying" if (is_varying_array($e));
	return "inline" if (is_inline_array($e));
	return "fixed" if (is_fixed_array($e));

	return undef;
}

#####################################################################
# work out the correct alignment for a structure or union
sub find_largest_alignment($)
{
	my $s = shift;

	my $align = 1;
	for my $e (@{$s->{ELEMENTS}}) {
		my $a = 1;

		if (Ndr::need_wire_pointer($e)) {
			$a = 4; 
		} else { 
			$a = align_type($e->{TYPE}); 
		}

		$align = $a if ($align < $a);
	}

	return $align;
}

#####################################################################
# align a type
sub align_type
{
	my $e = shift;

	unless (typelist::hasType($e)) {
	    # it must be an external type - all we can do is guess 
		# print "Warning: assuming alignment of unknown type '$e' is 4\n";
	    return 4;
	}

	my $dt = typelist::getType($e)->{DATA};

	if ($dt->{TYPE} eq "ENUM") {
		return align_type(typelist::enum_type_fn($dt));
	} elsif ($dt->{TYPE} eq "BITMAP") {
		return align_type(typelist::bitmap_type_fn($dt));
	} elsif (($dt->{TYPE} eq "STRUCT") or ($dt->{TYPE} eq "UNION")) {
		return find_largest_alignment($dt);
	} elsif ($dt->{TYPE} eq "SCALAR") {
		return typelist::getScalarAlignment($dt->{NAME});
	}

	die("Unknown data type type $dt->{TYPE}");
}

# determine if an element needs a reference pointer on the wire
# in its NDR representation
sub need_wire_pointer($)
{
	my $e = shift;

	my $n = $e->{POINTERS};
	my $pt = pointer_type($e);

	# Top level "ref" pointers do not have a referrent identifier
	if (	defined($pt) 
		and $pt eq "ref" 
		and $e->{PARENT}->{TYPE} eq "FUNCTION") 
	{
		$n--;
	}

	return $n;
}

sub ParseElement($)
{
	my $e = shift;

	return {
		NAME => $e->{NAME},
		PROPERTIES => $e->{PROPERTIES},
		LEVELS => GetElementLevelTable($e)
	};
}

sub ParseStruct($)
{
	my $e = shift;
	my @elements = ();

	foreach my $x (@{$e->{ELEMENTS}}) 
	{
		push @elements, ParseElement($x);
	}

	return {
		TYPE => "STRUCT",
		ELEMENTS => \@elements,
		PROPERTIES => $e->{PROPERTIES}
	};
}

sub ParseUnion($)
{
	my $e = shift;
	my @elements = ();
	
	foreach my $x (@{$e->{ELEMENTS}}) 
	{
		my $t;
		if ($x->{TYPE} eq "EMPTY") {
			$t = { TYPE => "EMPTY" };
		} else {
			$t = ParseElement($x);
			if (util::has_property($t, "default")) {
				$t->{DEFAULT} = "default";
			} else {
				$t->{CASE} = $t->{PROPERTIES}->{CASE};
			}
		}
		push @elements, $t;
	}

	return {
		TYPE => "UNION",
		ELEMENTS => \@elements,
		PROPERTIES => $e->{PROPERTIES}
	};
}

sub ParseEnum($)
{
	my $e = shift;

	return {
		TYPE => "ENUM",
		ELEMENTS => $e->{ELEMENTS},
		PROPERTIES => $e->{PROPERTIES}
	};
}

sub ParseBitmap($)
{
	my $e = shift;

	return {
		TYPE => "BITMAP",
		ELEMENTS => $e->{ELEMENTS},
		PROPERTIES => $e->{PROPERTIES}
	};
}

sub ParseTypedef($$)
{
	my $ndr = shift;
	my $d = shift;
	my $data;

	if ($d->{DATA}->{TYPE} eq "STRUCT" or $d->{DATA}->{TYPE} eq "UNION") {
		CheckPointerTypes($d->{DATA}, $ndr->{PROPERTIES}->{pointer_default});
	}

	if (defined($d->{PROPERTIES}) && !defined($d->{DATA}->{PROPERTIES})) {
		$d->{DATA}->{PROPERTIES} = $d->{PROPERTIES};
	}

	if ($d->{DATA}->{TYPE} eq "STRUCT") {
		$data = ParseStruct($d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq "UNION") {
		$data = ParseUnion($d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq "ENUM") {
		$data = ParseEnum($d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq "BITMAP") {
		$data = ParseBitmap($d->{DATA});
	} else {
		die("Unknown data type '$d->{DATA}->{TYPE}'");
	}

	$data->{ALIGN} = align_type($d->{NAME});

	return {
		NAME => $d->{NAME},
		TYPE => "TYPEDEF",
		PROPERTIES => $d->{PROPERTIES},
		DATA => $data
	};
}

sub ParseFunction($$)
{
	my $ndr = shift;
	my $d = shift;
	my @in = ();
	my @out = ();

	CheckPointerTypes($d, 
		$ndr->{PROPERTIES}->{pointer_default}  # MIDL defaults to "ref"
	);

	foreach my $x (@{$d->{ELEMENTS}}) {
		if (util::has_property($x, "in")) {
			push (@in, ParseElement($x));
		}
		if (util::has_property($x, "out")) {
			push (@out, ParseElement($x));
		}
	}
	
	return {
			NAME => $d->{NAME},
			TYPE => "FUNCTION",
			RETURN_TYPE => $d->{RETURN_TYPE},
			PROPERTIES => $d->{PROPERTIES},
			ELEMENTS => {
				IN => \@in,
				OUT => \@out
			}
		};
}

sub CheckPointerTypes($$)
{
	my $s = shift;
	my $default = shift;

	foreach my $e (@{$s->{ELEMENTS}}) {
		if ($e->{POINTERS}) {
			if (not defined(Ndr::pointer_type($e))) {
				$e->{PROPERTIES}->{$default} = 1;
			}

			if (Ndr::pointer_type($e) eq "ptr") {
				print "Warning: ptr is not supported by pidl yet\n";
			}
		}
	}
}

sub ParseInterface($)
{
	my $idl = shift;
	my @functions = ();
	my @typedefs = ();
	my $version;

	if (not util::has_property($idl, "pointer_default")) {
		# MIDL defaults to "ptr" in DCE compatible mode (/osf)
		# and "unique" in Microsoft Extensions mode (default)
		$idl->{PROPERTIES}->{pointer_default} = "unique";
	}

	foreach my $d (@{$idl->{DATA}}) {
		if ($d->{TYPE} eq "DECLARE" or $d->{TYPE} eq "TYPEDEF") {
			push (@typedefs, ParseTypedef($idl, $d));
		}

		if ($d->{TYPE} eq "FUNCTION") {
			push (@functions, ParseFunction($idl, $d));
		}
	}
	
	$version = "0.0";

	if(defined $idl->{PROPERTIES}->{version}) { 
		$version = $idl->{PROPERTIES}->{version}; 
	}
	

	return { 
		NAME => $idl->{NAME},
		UUID => util::has_property($idl, "uuid"),
		VERSION => $version,
		TYPE => "INTERFACE",
		PROPERTIES => $idl->{PROPERTIES},
		FUNCTIONS => \@functions,
		TYPEDEFS => \@typedefs
	};
}

# Convert a IDL tree to a NDR tree
# Gives a result tree describing all that's necessary for easily generating
# NDR parsers
# - list of interfaces
#  - list with functions
#   - list with in elements
#   - list with out elements
#  - list of typedefs
#   - list with structs
#    - alignment of structure
#    - list with elements
#   - list with unions
#    - alignment of union
#    - list with elements
#   - list with enums
#    - base type
#   - list with bitmaps
#    - base type
# per element: 
#  - alignment
#  - "level" table
# properties are saved
# pointer types explicitly specified
sub Parse($)
{
	my $idl = shift;
	my @ndr = ();

	foreach my $x (@{$idl}) {
		push @ndr, ParseInterface($x);
	}

	return \@ndr;
}

1;
