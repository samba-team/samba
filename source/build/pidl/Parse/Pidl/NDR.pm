###################################################
# Samba4 NDR info tree generator
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# Copyright jelmer@samba.org 2004-2005
# released under the GNU GPL

package Parse::Pidl::NDR;

use strict;
use Parse::Pidl::Typelist;

sub nonfatal($$)
{
	my ($e,$s) = @_;
	warn ("$e->{FILE}:$e->{LINE}: Warning: $s\n");
}

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

	if (Parse::Pidl::Util::has_property($e, "size_is")) {
		@size_is = split /,/, Parse::Pidl::Util::has_property($e, "size_is");
	}

	if (Parse::Pidl::Util::has_property($e, "length_is")) {
		@length_is = split /,/, Parse::Pidl::Util::has_property($e, "length_is");
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
		my $is_string = 0;

		if ($d eq "*") {
			$is_conformant = 1;
			if ($size = shift @size_is) {
			} elsif ((scalar(@size_is) == 0) and Parse::Pidl::Util::has_property($e, "string")) {
				$is_string = 1;
				delete($e->{PROPERTIES}->{string});
			} else {
				print "$e->{FILE}:$e->{LINE}: Must specify size_is() for conformant array!\n";
				exit 1;
			}

			if (($length = shift @length_is) or $is_string) {
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
			IS_SURROUNDING => "$is_surrounding",
			IS_ZERO_TERMINATED => "$is_string",
			IS_VARYING => "$is_varying",
			IS_CONFORMANT => "$is_conformant",
			IS_FIXED => (not $is_conformant and Parse::Pidl::Util::is_constant($size)),
			IS_INLINE => (not $is_conformant and not Parse::Pidl::Util::is_constant($size))
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

		my $array_size = shift @size_is;
		my $array_length;
		my $is_varying;
		my $is_conformant;
		my $is_string = 0;
		if ($array_size) {
			$is_conformant = 1;
			if ($array_length = shift @length_is) {
				$is_varying = 1;
			} else {
				$array_length = $array_size;
				$is_varying =0;
			}
		} 
		
		if (scalar(@size_is) == 0 and Parse::Pidl::Util::has_property($e, "string")) {
			$is_string = 1;
			$is_varying = $is_conformant = Parse::Pidl::Util::has_property($e, "noheader")?0:1;
			delete($e->{PROPERTIES}->{string});
		}

		if ($array_size or $is_string) {
			push (@$order, {
				TYPE => "ARRAY",
				IS_ZERO_TERMINATED => "$is_string",
				SIZE_IS => $array_size,
				LENGTH_IS => $array_length,
				IS_DEFERRED => "$is_deferred",
				IS_SURROUNDING => 0,
				IS_VARYING => "$is_varying",
				IS_CONFORMANT => "$is_conformant",
				IS_FIXED => 0,
				IS_INLINE => 0,
			});

			$is_deferred = 0;
		} 
	}

	if (defined(Parse::Pidl::Util::has_property($e, "subcontext"))) {
		my $hdr_size = Parse::Pidl::Util::has_property($e, "subcontext");
		my $subsize = Parse::Pidl::Util::has_property($e, "subcontext_size");
		if (not defined($subsize)) { 
			$subsize = -1; 
		}
		
		push (@$order, {
			TYPE => "SUBCONTEXT",
			HEADER_SIZE => $hdr_size,
			SUBCONTEXT_SIZE => $subsize,
			IS_DEFERRED => $is_deferred,
			COMPRESSION => Parse::Pidl::Util::has_property($e, "compression"),
			OBFUSCATION => Parse::Pidl::Util::has_property($e, "obfuscation")
		});
	}

	if (my $switch = Parse::Pidl::Util::has_property($e, "switch_is")) {
		push (@$order, {
			TYPE => "SWITCH", 
			SWITCH_IS => $switch,
			IS_DEFERRED => $is_deferred
		});
	}

	if (scalar(@size_is) > 0) {
		nonfatal($e, "size_is() on non-array element");
	}

	if (scalar(@length_is) > 0) {
		nonfatal($e, "length_is() on non-array element");
	}

	if (Parse::Pidl::Util::has_property($e, "string")) {
		nonfatal($e, "string() attribute on non-array element");
	}


	push (@$order, {
		TYPE => "DATA",
		DATA_TYPE => $e->{TYPE},
		IS_DEFERRED => $is_deferred,
		CONTAINS_DEFERRED => can_contain_deferred($e),
		IS_SURROUNDING => 0 #FIXME
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
	return 0 if (Parse::Pidl::Typelist::is_scalar($e->{TYPE}));
	return 1 unless (Parse::Pidl::Typelist::hasType($e->{TYPE})); # assume the worst

	my $type = Parse::Pidl::Typelist::getType($e->{TYPE});

	foreach my $x (@{$type->{DATA}->{ELEMENTS}}) {
		return 1 if (can_contain_deferred ($x));
	}
	
	return 0;
}

sub pointer_type($)
{
	my $e = shift;

	return undef unless $e->{POINTERS};
	
	return "ref" if (Parse::Pidl::Util::has_property($e, "ref"));
	return "ptr" if (Parse::Pidl::Util::has_property($e, "ptr"));
	return "sptr" if (Parse::Pidl::Util::has_property($e, "sptr"));
	return "unique" if (Parse::Pidl::Util::has_property($e, "unique"));
	return "relative" if (Parse::Pidl::Util::has_property($e, "relative"));
	return "ignore" if (Parse::Pidl::Util::has_property($e, "ignore"));

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

		if ($e->{POINTERS}) {
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

	unless (Parse::Pidl::Typelist::hasType($e)) {
	    # it must be an external type - all we can do is guess 
		# print "Warning: assuming alignment of unknown type '$e' is 4\n";
	    return 4;
	}

	my $dt = Parse::Pidl::Typelist::getType($e)->{DATA};

	if ($dt->{TYPE} eq "ENUM") {
		return align_type(Parse::Pidl::Typelist::enum_type_fn($dt));
	} elsif ($dt->{TYPE} eq "BITMAP") {
		return align_type(Parse::Pidl::Typelist::bitmap_type_fn($dt));
	} elsif (($dt->{TYPE} eq "STRUCT") or ($dt->{TYPE} eq "UNION")) {
		return find_largest_alignment($dt);
	} elsif ($dt->{TYPE} eq "SCALAR") {
		return Parse::Pidl::Typelist::getScalarAlignment($dt->{NAME});
	}

	die("Unknown data type type $dt->{TYPE}");
}

sub ParseElement($)
{
	my $e = shift;

	return {
		NAME => $e->{NAME},
		TYPE => $e->{TYPE},
		PROPERTIES => $e->{PROPERTIES},
		LEVELS => GetElementLevelTable($e),
		ALIGN => align_type($e->{TYPE})
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
	    &&  Parse::Pidl::Util::property_matches($e, "flag", ".*LIBNDR_FLAG_STR_CONFORMANT.*")) {
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
	my $switch_type = Parse::Pidl::Util::has_property($e, "switch_type");
	unless (defined($switch_type)) { $switch_type = "uint32"; }

	if (Parse::Pidl::Util::has_property($e, "nodiscriminant")) { $switch_type = undef; }
	
	foreach my $x (@{$e->{ELEMENTS}}) 
	{
		my $t;
		if ($x->{TYPE} eq "EMPTY") {
			$t = { TYPE => "EMPTY" };
		} else {
			$t = ParseElement($x);
		}
		if (Parse::Pidl::Util::has_property($x, "default")) {
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
		BASE_TYPE => Parse::Pidl::Typelist::enum_type_fn($e),
		ELEMENTS => $e->{ELEMENTS},
		PROPERTIES => $e->{PROPERTIES}
	};
}

sub ParseBitmap($)
{
	my $e = shift;

	return {
		TYPE => "BITMAP",
		BASE_TYPE => Parse::Pidl::Typelist::bitmap_type_fn($e),
		ELEMENTS => $e->{ELEMENTS},
		PROPERTIES => $e->{PROPERTIES}
	};
}

sub ParseTypedef($$)
{
	my ($ndr,$d) = @_;
	my $data;

	if ($d->{DATA}->{TYPE} eq "STRUCT" or $d->{DATA}->{TYPE} eq "UNION") {
		CheckPointerTypes($d->{DATA}, $ndr->{PROPERTIES}->{pointer_default});
	}

	if (defined($d->{PROPERTIES}) && !defined($d->{DATA}->{PROPERTIES})) {
		$d->{DATA}->{PROPERTIES} = $d->{PROPERTIES};
	}

	$data = {
		STRUCT => \&ParseStruct,
		UNION => \&ParseUnion,
		ENUM => \&ParseEnum,
		BITMAP => \&ParseBitmap
	}->{$d->{DATA}->{TYPE}}->($d->{DATA});

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
	my ($ndr,$d) = @_;

	return $d;
}

sub ParseFunction($$$)
{
	my ($ndr,$d,$opnum) = @_;
	my @elements = ();
	my $rettype = undef;
	my $thisopnum = undef;

	CheckPointerTypes($d, $ndr->{PROPERTIES}->{pointer_default_top});

	if (not defined($d->{PROPERTIES}{noopnum})) {
		$thisopnum = ${$opnum};
		${$opnum}++;
	}

	foreach my $x (@{$d->{ELEMENTS}}) {
		my $e = ParseElement($x);
		push (@{$e->{DIRECTION}}, "in") if (Parse::Pidl::Util::has_property($x, "in"));
		push (@{$e->{DIRECTION}}, "out") if (Parse::Pidl::Util::has_property($x, "out"));
		push (@elements, $e);
	}

	if ($d->{RETURN_TYPE} ne "void") {
		$rettype = $d->{RETURN_TYPE};
	}
	
	return {
			NAME => $d->{NAME},
			TYPE => "FUNCTION",
			OPNUM => $thisopnum,
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
		if ($e->{POINTERS} and not defined(pointer_type($e))) {
			$e->{PROPERTIES}->{$default} = 1;
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

	if (not Parse::Pidl::Util::has_property($idl, "pointer_default")) {
		# MIDL defaults to "ptr" in DCE compatible mode (/osf)
		# and "unique" in Microsoft Extensions mode (default)
		$idl->{PROPERTIES}->{pointer_default} = "unique";
	}

	if (not Parse::Pidl::Util::has_property($idl, "pointer_default_top")) {
		$idl->{PROPERTIES}->{pointer_default_top} = "ref";
	}

	foreach my $d (@{$idl->{DATA}}) {
		if ($d->{TYPE} eq "TYPEDEF") {
			push (@typedefs, ParseTypedef($idl, $d));
		}

		if ($d->{TYPE} eq "DECLARE") {
			push (@declares, $d);
		}

		if ($d->{TYPE} eq "FUNCTION") {
			push (@functions, ParseFunction($idl, $d, \$opnum));
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
		UUID => Parse::Pidl::Util::has_property($idl, "uuid"),
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
# NDR parsers / generators
sub Parse($)
{
	my $idl = shift;
	my @ndr = ();

	push(@ndr, ParseInterface($_)) foreach (@{$idl});

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
	my ($e,$fl) = @_;
	my $prev = undef;

	foreach my $l (@{$e->{LEVELS}}) {
		(return $prev) if ($l == $fl);
		$prev = $l;
	}

	return undef;
}

sub ContainsDeferred($$)
{
	my ($e,$l) = @_;

	do {
		return 1 if ($l->{IS_DEFERRED}); 
		return 1 if ($l->{CONTAINS_DEFERRED});
	} while ($l = GetNextLevel($e,$l));
	
	return 0;
}

1;
