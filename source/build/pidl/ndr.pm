###################################################
# Samba4 NDR info tree generator
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# Copyright jelmer@samba.org 2004-2005
# released under the GNU GPL

package Ndr;

use strict;
use pidl::typelist;

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

	my $order = [];
	my $is_deferred = 0;
	my @bracket_array = ();
	my @length_is = ();
	my @size_is = ();

	if (util::has_property($e, "size_is")) {
		@size_is = split /,/, util::has_property($e, "size_is");
	}

	if (util::has_property($e, "length_is")) {
		@length_is = split /,/, util::has_property($e, "length_is");
	}

	if (defined($e->{ARRAY_LEN})) {
		@bracket_array = @{$e->{ARRAY_LEN}};
	}
	
	# Parse the [][][][] style array stuff
	foreach my $d (@bracket_array) {
		my $size = $d;
		my $length = $d;
		my $is_surrounding = 0;
		my $is_varying = 0;
		my $is_conformant = 0;

		if ($d eq "*") {
			$is_conformant = 1;
			unless ($size = shift @size_is) {
				print "$e->{FILE}:$e->{LINE}: Must specify size_is() for conformant array!\n";
				exit 1;
			}

			if ($length = shift @length_is) {
				$is_varying = 1;
			} else {
				$length = $size;
			}

			if ($e == $e->{PARENT}->{ELEMENTS}[-1] 
				and $e->{PARENT}->{TYPE} ne "FUNCTION") {
				$is_surrounding = 1;
			}
		}

		push (@$order, {
			TYPE => "ARRAY",
			SIZE_IS => $size,
			LENGTH_IS => $length,
			IS_DEFERRED => "$is_deferred",
			# Inline arrays (which are a pidl extension) are never encoded
			# as surrounding the struct they're part of
			IS_SURROUNDING => "$is_surrounding",
			IS_VARYING => "$is_varying",
			IS_CONFORMANT => "$is_conformant",
			IS_FIXED => (not $is_conformant and util::is_constant($size)),
			NO_METADATA => (not $is_conformant),
			IS_INLINE => (not $is_conformant and not util::is_constant($size))
		});
	}

	# Next, all the pointers
	foreach my $i (1..$e->{POINTERS}) {
		my $pt = pointer_type($e);

		my $level = "EMBEDDED";
		# Top level "ref" pointers do not have a referrent identifier
		$level = "TOP" if ( defined($pt) 
				and $i == 1
				and $e->{PARENT}->{TYPE} eq "FUNCTION");

		push (@$order, { 
			TYPE => "POINTER",
			# for now, there can only be one pointer type per element
			POINTER_TYPE => pointer_type($e),
			IS_DEFERRED => "$is_deferred",
			LEVEL => $level
		});
		
		# everything that follows will be deferred
		$is_deferred = 1 if ($e->{PARENT}->{TYPE} ne "FUNCTION");

		my $array_size;
		my $array_length;
		if ($array_size = shift @size_is) {
			my $is_varying = 0;
			if ($array_length = shift @length_is) {
				$is_varying = 1;
			} else {
				$array_length = $array_size;
			}

			push (@$order, {
				TYPE => "ARRAY",
				SIZE_IS => $array_size,
				LENGTH_IS => $array_length,
				IS_DEFERRED => "$is_deferred",
				IS_SURROUNDING => 0,
				IS_VARYING => "$is_varying",
				IS_CONFORMANT => 1,
				IS_FIXED => 0,
				NO_METADATA => 0,
				IS_INLINE => 0,
			});

			$is_deferred = 0;
		}
	}

	if (my $hdr_size = util::has_property($e, "subcontext")) {
		my $subsize = util::has_property($e, "subcontext_size");
		if (not defined($subsize)) { 
			$subsize = -1; 
		}
		
		push (@$order, {
			TYPE => "SUBCONTEXT",
			HEADER_SIZE => $hdr_size,
			SUBCONTEXT_SIZE => $subsize,
			IS_DEFERRED => $is_deferred,
			COMPRESSION => util::has_property($e, "compression"),
			OBFUSCATION => util::has_property($e, "obfuscation")
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
		IS_DEFERRED => $is_deferred,
		CONTAINS_DEFERRED => can_contain_deferred($e),
		IS_SURROUNDING => is_surrounding_string($e)
	});

	my $i = 0;
	foreach (@$order) { $_->{LEVEL_INDEX} = $i; $i+=1; }

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

	return 0 unless(typelist::hasType($type));

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

sub is_surrounding_string($)
{
	my $e = shift;

	return 0; #FIXME

	return ($e->{TYPE} eq "string") and ($e->{POINTERS} == 0) 
		and util::property_matches($e, "flag", ".*LIBNDR_FLAG_STR_CONFORMANT.*") 
		and $e->{PARENT}->{TYPE} ne "FUNCTION";
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

my %scalar_alignments = 
(
     "char"           => 1,
     "int8"           => 1,
     "uint8"          => 1,
     "short"          => 2,
     "wchar_t"        => 2,
     "int16"          => 2,
     "uint16"         => 2,
     "long"           => 4,
     "int32"          => 4,
     "uint32"         => 4,
     "dlong"          => 4,
     "udlong"         => 4,
     "udlongr"        => 4,
     "NTTIME"         => 4,
     "NTTIME_1sec"    => 4,
     "time_t"         => 4,
     "DATA_BLOB"      => 4,
     "error_status_t" => 4,
     "WERROR"         => 4,
	 "NTSTATUS" 	  => 4,
     "boolean32"      => 4,
     "unsigned32"     => 4,
     "ipv4address"    => 4,
     "hyper"          => 8,
     "NTTIME_hyper"   => 8
);

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
		return $scalar_alignments{$dt->{NAME}};
	} else { 
		die("Unknown data type type $dt->{TYPE}");
	}
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
		TYPE => $e->{TYPE},
		PROPERTIES => $e->{PROPERTIES},
		LEVELS => GetElementLevelTable($e)
	};
}

sub ParseStruct($)
{
	my $struct = shift;
	my @elements = ();
	my $surrounding = undef;

	foreach my $x (@{$struct->{ELEMENTS}}) 
	{
		push @elements, ParseElement($x);
	}

	my $e = $elements[-1];
	if (defined($e) and defined($e->{LEVELS}[0]->{IS_SURROUNDING}) and
		$e->{LEVELS}[0]->{IS_SURROUNDING}) {
		$surrounding = $e;
	}

	if (defined $e->{TYPE} && $e->{TYPE} eq "string"
	    &&  util::property_matches($e, "flag", ".*LIBNDR_FLAG_STR_CONFORMANT.*")) {
		$surrounding = $struct->{ELEMENTS}[-1];
	}
		
	return {
		TYPE => "STRUCT",
		SURROUNDING_ELEMENT => $surrounding,
		ELEMENTS => \@elements,
		PROPERTIES => $struct->{PROPERTIES}
	};
}

sub ParseUnion($)
{
	my $e = shift;
	my @elements = ();
	my $switch_type = util::has_property($e, "switch_type");
	unless (defined($switch_type)) { $switch_type = "uint32"; }

	if (util::has_property($e, "nodiscriminant")) { $switch_type = undef; }
	
	foreach my $x (@{$e->{ELEMENTS}}) 
	{
		my $t;
		if ($x->{TYPE} eq "EMPTY") {
			$t = { TYPE => "EMPTY" };
		} else {
			$t = ParseElement($x);
		}
		if (util::has_property($x, "default")) {
			$t->{CASE} = "default";
		} elsif (defined($x->{PROPERTIES}->{case})) {
			$t->{CASE} = "case $x->{PROPERTIES}->{case}";
		} else {
			die("Union element $x->{NAME} has neither default nor case property");
		}
		push @elements, $t;
	}

	return {
		TYPE => "UNION",
		SWITCH_TYPE => $switch_type,
		ELEMENTS => \@elements,
		PROPERTIES => $e->{PROPERTIES}
	};
}

sub ParseEnum($)
{
	my $e = shift;

	return {
		TYPE => "ENUM",
		BASE_TYPE => typelist::enum_type_fn($e),
		ELEMENTS => $e->{ELEMENTS},
		PROPERTIES => $e->{PROPERTIES}
	};
}

sub ParseBitmap($)
{
	my $e = shift;

	return {
		TYPE => "BITMAP",
		BASE_TYPE => typelist::bitmap_type_fn($e),
		ELEMENTS => $e->{ELEMENTS},
		PROPERTIES => $e->{PROPERTIES}
	};
}

sub ParseDeclare($$)
{
	my $ndr = shift;
	my $d = shift;

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
		TYPE => $d->{TYPE},
		PROPERTIES => $d->{PROPERTIES},
		DATA => $data
	};
}

sub ParseConst($$)
{
	my $ndr = shift;
	my $d = shift;

	return $d;
}

sub ParseFunction($$$)
{
	my $ndr = shift;
	my $d = shift;
	my $opnum = shift;
	my @elements = ();
	my $rettype = undef;

	CheckPointerTypes($d, 
		$ndr->{PROPERTIES}->{pointer_default_top}
	);

	foreach my $x (@{$d->{ELEMENTS}}) {
		my $e = ParseElement($x);
		if (util::has_property($x, "in")) {
			push (@{$e->{DIRECTION}}, "in");
		}

		if (util::has_property($x, "out")) {
			push (@{$e->{DIRECTION}}, "out");
		}

		push (@elements, $e);
	}

	if ($d->{RETURN_TYPE} ne "void") {
		$rettype = $d->{RETURN_TYPE};
	}
	
	return {
			NAME => $d->{NAME},
			TYPE => "FUNCTION",
			OPNUM => $opnum,
			RETURN_TYPE => $rettype,
			PROPERTIES => $d->{PROPERTIES},
			ELEMENTS => \@elements
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
	my @typedefs = ();
	my @consts = ();
	my @functions = ();
	my @endpoints;
	my @declares = ();
	my $opnum = 0;
	my $version;

	if (not util::has_property($idl, "pointer_default")) {
		# MIDL defaults to "ptr" in DCE compatible mode (/osf)
		# and "unique" in Microsoft Extensions mode (default)
		$idl->{PROPERTIES}->{pointer_default} = "unique";
	}

	if (not util::has_property($idl, "pointer_default_top")) {
		$idl->{PROPERTIES}->{pointer_default_top} = "ref";
	}

	foreach my $d (@{$idl->{DATA}}) {
		if ($d->{TYPE} eq "TYPEDEF") {
			push (@typedefs, ParseTypedef($idl, $d));
		}

		if ($d->{TYPE} eq "DECLARE") {
			push (@declares, ParseDeclare($idl, $d));
		}

		if ($d->{TYPE} eq "FUNCTION") {
			push (@functions, ParseFunction($idl, $d, $opnum));
			$opnum+=1;
		}

		if ($d->{TYPE} eq "CONST") {
			push (@consts, ParseConst($idl, $d));
		}
	}

	$version = "0.0";

	if(defined $idl->{PROPERTIES}->{version}) { 
		$version = $idl->{PROPERTIES}->{version}; 
	}

	# If no endpoint is set, default to the interface name as a named pipe
	if (!defined $idl->{PROPERTIES}->{endpoint}) {
		push @endpoints, "\"ncacn_np:[\\\\pipe\\\\" . $idl->{NAME} . "]\"";
	} else {
		@endpoints = split / /, $idl->{PROPERTIES}->{endpoint};
	}

	return { 
		NAME => $idl->{NAME},
		UUID => util::has_property($idl, "uuid"),
		VERSION => $version,
		TYPE => "INTERFACE",
		PROPERTIES => $idl->{PROPERTIES},
		FUNCTIONS => \@functions,
		CONSTS => \@consts,
		TYPEDEFS => \@typedefs,
		DECLARES => \@declares,
		ENDPOINTS => \@endpoints
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

sub GetNextLevel($$)
{
	my $e = shift;
	my $fl = shift;

	my $seen = 0;

	foreach my $l (@{$e->{LEVELS}}) {
		return $l if ($seen);
		($seen = 1) if ($l == $fl);
	}

	return undef;
}

sub GetPrevLevel($$)
{
	my $e = shift;
	my $fl = shift;
	my $prev = undef;

	foreach my $l (@{$e->{LEVELS}}) {
		(return $prev) if ($l == $fl);
		$prev = $l;
	}

	return undef;
}

sub ContainsDeferred($$)
{
	my $e = shift;
	my $l = shift;

	do {
		return 1 if ($l->{IS_DEFERRED}); 
		return 1 if ($l->{CONTAINS_DEFERRED});
	} while ($l = Ndr::GetNextLevel($e,$l));
	
	return 0;
}


1;
