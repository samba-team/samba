##################################################
# Samba4 NDR parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# Copyright jelmer@samba.org 2004-2005
# released under the GNU GPL

package EthParser;

use strict;
use pidl::typelist;
use pidl::ndr;

# the list of needed functions

# list of known types
my %typefamily;


sub NeededFunction($$)
{
	my $fn = shift;
	my $needed = shift;
	$needed->{"pull_$fn->{NAME}"} = 1;
	foreach my $e (@{$fn->{ELEMENTS}}) {
		$e->{PARENT} = $fn;
		unless(defined($needed->{"pull_$e->{TYPE}"})) {
			$needed->{"pull_$e->{TYPE}"} = 1;
		}

		# for Ethereal
	    $needed->{"hf_$fn->{NAME}_$e->{NAME}"} = {
			'name' => field2name($e->{NAME}),
			'type' => $e->{TYPE},
			'ft'   => type2ft($e->{TYPE}),
			'base' => elementbase($e)
		};
	    $needed->{"hf_$e->{TYPE}"} = {
			'name' => field2name($e->{NAME}),
			'type' => $e->{TYPE},
			'ft'   => type2ft($e->{TYPE}),
			'base' => elementbase($e)
		};
	    $needed->{"ett_$e->{TYPE}"} = 1;
	}

	# Add entry for return value
	if (defined($fn->{RETURN_TYPE})) {
		$needed->{"hf_$fn->{NAME}_result"} = {
	    'name' => field2name('result'),
	    'type' => $fn->{RETURN_TYPE},
	    'ft' => type2ft($fn->{RETURN_TYPE}),
	    'base' => elementbase($fn)
	    };
	}
}

sub NeededTypedef($$)
{
	my $t = shift;
	my $needed = shift;

	if (util::has_property($t, "public")) {
		$needed->{"pull_$t->{NAME}"} = not util::has_property($t, "nopull");
	}

	if ($t->{DATA}->{TYPE} eq "STRUCT" or $t->{DATA}->{TYPE} eq "UNION") {

		for my $e (@{$t->{DATA}->{ELEMENTS}}) {
			$e->{PARENT} = $t->{DATA};
			if ($needed->{"pull_$t->{NAME}"} and
				not defined($needed->{"pull_$e->{TYPE}"})) {
				$needed->{"pull_$e->{TYPE}"} = 1;
			}

	        $needed->{"hf_$t->{NAME}_$e->{NAME}"} = {
				'name' => field2name($e->{NAME}),
				'type' => $e->{TYPE},
				'ft'   => type2ft($e->{TYPE}),
				'base' => elementbase($e)
			};
			$needed->{"ett_$e->{TYPE}"} = 1;
		 }
	}

	if ($t->{DATA}->{TYPE} eq "ENUM") {

		$needed->{"hf_$t->{NAME}"} = {
			'name' => field2name($t->{NAME}),
			'ft' => 'FT_UINT16',
			'base' => 'BASE_DEC',
			'strings' => "VALS($t->{NAME}_vals)"
		};
		$needed->{"ett_$t->{NAME}"} = 1;
	}

	if ($t->{DATA}->{TYPE} eq "BITMAP") {
    	$needed->{BITMAPS}->{$t->{NAME}} = $t;

		foreach my $e (@{$t->{DATA}{ELEMENTS}}) {
			$e =~ /^(.*?) \( (.*?) \)$/;
			$needed->{"hf_$t->{NAME}_$1"} = {
				'name' => "$1",
				'ft' => "FT_BOOLEAN",
				'base' => bitmapbase($t),
				'bitmask' => "$2"
			};
		}
		$needed->{"ett_$t->{NAME}"} = 1;
	}
}

#####################################################################
# work out what parse functions are needed
sub NeededInterface($)
{
	my($interface) = shift;
	my %needed = ();

	$needed{"hf_$interface->{NAME}_opnum"} = {
		'name' => "Operation",
		'ft'   => "FT_UINT16",
		'base' => "BASE_DEC"
	};

	$needed{"ett_dcerpc_$interface->{NAME}"} = 1;
	
	foreach my $d (@{$interface->{FUNCTIONS}}) {
	    NeededFunction($d, \%needed);
	}
	foreach my $d (reverse @{$interface->{TYPEDEFS}}) {
	    NeededTypedef($d, \%needed);
	}

	return \%needed;
}

sub type2ft($)
{
    my($t) = shift;
 
    return "FT_UINT$1" if $t =~ /uint(8|16|32|64)/;
    return "FT_INT$1" if $t =~ /int(8|16|32|64)/;
    return "FT_UINT64", if $t eq "HYPER_T" or $t eq "NTTIME"
	or $t eq "NTTIME_1sec" or $t eq "NTTIME_hyper" or $t eq "hyper";
   
   # Type is an enum

    return "FT_UINT16";
}

# Determine the display base for an element

sub elementbase($)
{
    my($e) = shift;

    if (my $base = util::has_property($e, "display")) {
	return "BASE_" . uc($base);
    }
 
    return "BASE_DEC", if $e->{TYPE} eq "ENUM";
    return "BASE_DEC", if $e->{TYPE} =~ /u?int(8|16|32|64)/;
    return "BASE_DEC", if $e->{TYPE} eq "NTTIME" or $e->{TYPE} eq "HYPER_T";

    # Probably an enum

    return "BASE_DEC";
}

# Convert a IDL structure field name (e.g access_mask) to a prettier
# string like 'Access Mask'.

sub field2name($)
{
    my($field) = shift;

    $field =~ s/_/ /g;		# Replace underscores with spaces
    $field =~ s/(\w+)/\u\L$1/g;	# Capitalise each word
    
    return $field;
}

sub bitmapbase($)
{
    my $e = shift;

    return "16", if util::has_property($e->{DATA}, "bitmap16bit");
    return "8", if util::has_property($e->{DATA}, "bitmap8bit");

    return "32";
}

sub get_typefamily($)
{
	my $n = shift;
	return $typefamily{$n};
}

sub append_prefix($$)
{
	my $e = shift;
	my $var_name = shift;
	my $pointers = 0;

	foreach my $l (@{$e->{LEVELS}}) {
		if ($l->{TYPE} eq "POINTER") {
			$pointers++;
		} elsif ($l->{TYPE} eq "ARRAY") {
			if (($pointers == 0) and 
			    (not $l->{IS_FIXED}) and
			    (not $l->{IS_INLINE})) {
				return get_value_of($var_name) 
			}
		} elsif ($l->{TYPE} eq "DATA") {
			if ($l->{DATA_TYPE} eq "string" or
			    $l->{DATA_TYPE} eq "nbt_string") {
				return get_value_of($var_name) unless ($pointers);
			}
		}
	}
	
	return $var_name;
}

# see if a variable needs to be allocated by the NDR subsystem on pull
sub need_alloc($)
{
	my $e = shift;

	return 0;
}

sub get_pointer_to($)
{
	my $var_name = shift;
	
	if ($var_name =~ /^\*(.*)$/) {
		return $1;
	} elsif ($var_name =~ /^\&(.*)$/) {
	    return $var_name;
#		return "&($var_name)";
	} else {
		return "&$var_name";
	}
}

sub get_value_of($)
{
	my $var_name = shift;

	if ($var_name =~ /^\&(.*)$/) {
		return $1;
	} else {
		return "*$var_name";
	}
}

my $res;
my $tabs = "";
sub pidl($)
{
	my $d = shift;
	if ($d) {
		$res .= $tabs;
		$res .= $d;
	}
	$res .="\n";
}

sub indent()
{
	$tabs .= "\t";
}

sub deindent()
{
	$tabs = substr($tabs, 0, -1);
}

####################################################################
# work out the name of a size_is() variable
sub ParseExpr($$)
{
	my($orig_expr) = shift;
	my $varlist = shift;

	die("Undefined value in ParseExpr") if not defined($orig_expr);

	my $expr = $orig_expr;

	return $expr if (util::is_constant($expr));

	my $prefix = "";
	my $postfix = "";

	if ($expr =~ /\*(.*)/) {
		$expr = $1;
		$prefix = "*";
	}

	if ($expr =~ /^(.*)([\&\|\/+])(.*)$/) {
		$postfix = $2.$3;
		$expr = $1;
	}

	if (defined($varlist->{$expr})) {
		return $prefix.$varlist->{$expr}.$postfix;
	}

	return $prefix.$expr.$postfix;
}

#####################################################################
# check that a variable we get from ParseExpr isn't a null pointer
sub check_null_pointer($)
{
	my $size = shift;
	if ($size =~ /^\*/) {
		my $size2 = substr($size, 1);
		pidl "if ($size2 == NULL) return NT_STATUS_INVALID_PARAMETER_MIX;";
	}
}

#####################################################################
# check that a variable we get from ParseExpr isn't a null pointer
# void return varient
sub check_null_pointer_void($)
{
	my $size = shift;
	if ($size =~ /^\*/) {
		my $size2 = substr($size, 1);
		pidl "if ($size2 == NULL) return;";
	}
}

#####################################################################
# work out is a parse function should be declared static or not
sub fn_prefix($)
{
	my $fn = shift;

	return "" if (util::has_property($fn, "public"));
	return "static ";
}

###################################################################
# setup any special flags for an element or structure
sub start_flags($)
{
	my $e = shift;
	my $flags = util::has_property($e, "flag");
	if (defined $flags) {
		pidl "{ uint32_t _flags_save_$e->{TYPE} = ndr->flags;";
		pidl "ndr_set_flags(&ndr->flags, $flags);";
		indent;
	}
}

###################################################################
# end any special flags for an element or structure
sub end_flags($)
{
	my $e = shift;
	my $flags = util::has_property($e, "flag");
	if (defined $flags) {
		pidl "ndr->flags = _flags_save_$e->{TYPE};\n\t}";
		deindent;
	}
}

sub GenerateStructEnv($)
{
	my $x = shift;
	my %env;

	foreach my $e (@{$x->{ELEMENTS}}) {
		$env{$e->{NAME}} = "r->$e->{NAME}";
	}

	$env{"this"} = "r";

	return \%env;
}

sub GenerateFunctionEnv($)
{
	my $fn = shift;
	my %env;

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep (/out/, @{$e->{DIRECTION}})) {
			$env{$e->{NAME}} = "r->out.$e->{NAME}";
		}
		if (grep (/in/, @{$e->{DIRECTION}})) {
			$env{$e->{NAME}} = "r->in.$e->{NAME}";
		}
	}

	return \%env;
}

#####################################################################
sub ParseArrayPreceding($$$)
{
	my $e = shift;
	my $l = shift;
	my $var_name = shift;

	return if ($l->{NO_METADATA});
	
	# non fixed arrays encode the size just before the array
	pidl "ndr_pull_array_size(ndr, tree, " . get_pointer_to($var_name) . ");";
}

sub compression_alg($$)
{
	my $e = shift;
	my $l = shift;
	my $compression = $l->{COMPRESSION};
	my ($alg, $clen, $dlen) = split(/ /, $compression);

	return $alg;
}

sub compression_clen($$$)
{
	my $e = shift;
	my $l = shift;
	my $env = shift;
	my $compression = $l->{COMPRESSION};
	my ($alg, $clen, $dlen) = split(/ /, $compression);

	return ParseExpr($clen, $env);
}

sub compression_dlen($$$)
{
	my $e = shift;
	my $l = shift;
	my $env = shift;
	my $compression = $l->{COMPRESSION};
	my ($alg, $clen, $dlen) = split(/ /, $compression);

	return ParseExpr($dlen, $env);
}

sub ParseCompressionStart($$$$)
{
	my $e = shift;
	my $l = shift;
	my $subndr = shift;
	my $env = shift;
	my $comndr = $subndr."_compressed";
	my $alg = compression_alg($e, $l);
	my $dlen = compression_dlen($e, $l, $env);

	pidl "{";
	indent;
	pidl "struct pidl_pull *$comndr;";
	pidl "NDR_ALLOC($subndr, $comndr);";
	pidl "ndr_pull_compression($subndr, $comndr, $alg, $dlen);";

	return $comndr;
}

sub ParseCompressionEnd($$$)
{
	my $e = shift;
	my $l = shift;
	my $subndr = shift;
	my $comndr = $subndr."_compressed";

	deindent;
	pidl "}";
}

sub ParseObfuscationStart($$)
{
	my $e = shift;
	my $ndr = shift;
	my $obfuscation = util::has_property($e, "obfuscation");

	pidl "ndr_pull_obfuscation($ndr, $obfuscation);";

	return $ndr;
}

sub ParseObfuscationEnd($$)
{
	my $e = shift;
	my $ndr = shift;

	# nothing to do here
}

sub ParseSubcontextStart($$$$$$)
{
	my $e = shift;
	my $l = shift;
	my $ndr = shift;
	my $var_name = shift;
	my $ndr_flags = shift;	
	my $env = shift;
	my $retndr = "_ndr_$e->{NAME}";

	pidl "/* NDR_FLAGS $ndr_flags */";
	pidl "if ((ndr_flags) & NDR_SCALARS) {";
	indent;
	pidl "struct pidl_pull *$retndr;";
	pidl "NDR_ALLOC(ndr, $retndr);";
	pidl "ndr_pull_subcontext_header($ndr, $l->{HEADER_SIZE}, $l->{SUBCONTEXT_SIZE}, $retndr);"; 

	if (defined $l->{COMPRESSION}) {
		$retndr = ParseCompressionStart($e, $l, $retndr, $env);
	}

	if (defined $l->{OBFUSCATION}) {
		$retndr = ParseObfuscationStart($e, $retndr);
	}
	
	return ($retndr,$var_name);
}

sub ParseSubcontextEnd($$)
{
	my $e = shift;
	my $l = shift;
	my $ndr = "_ndr_$e->{NAME}";

	if (defined $l->{COMPRESSION}) {
		ParseCompressionEnd($e, $l, $ndr);
	}

	if (defined $l->{OBFUSCATION}) {
		ParseObfuscationEnd($e, $ndr);
	}

	my $advance;
	if (defined($l->{SUBCONTEXT_SIZE}) and ($l->{SUBCONTEXT_SIZE} ne "-1")) {
		$advance = $l->{SUBCONTEXT_SIZE};
	} elsif ($l->{HEADER_SIZE}) {
		$advance = "$ndr->data_size";
	} else {
		$advance = "$ndr->offset";
	}
	pidl "ndr_pull_advance(ndr, $advance);";
	deindent;
	pidl "}";
}

#####################################################################
# parse scalars in a structure element - pull size
sub ParseSwitch($$$$$$)
{
	my($e) = shift;
	my $l = shift;
	my $ndr = shift;
	my($var_name) = shift;
	my($ndr_flags) = shift;
	my $env = shift;
	my $switch_var = ParseExpr($l->{SWITCH_IS}, $env);

	check_null_pointer($switch_var);

	$var_name = get_pointer_to($var_name);
	pidl "ndr_pull_set_switch_value($ndr, $var_name, $switch_var);";

}

sub ParseData($$$$$)
{
	my $e = shift;
	my $l = shift;
	my $ndr = shift;
	my $var_name = shift;
	my $ndr_flags = shift;

	$var_name = get_pointer_to($var_name);

	#
	#  ALAND! for packet-dcerpc-lsa.c, uncommenting this code
	#  produces constructs like &(&r->string), to pass to another
	#  function, which gives compiler errors.
	#
	if ($l->{DATA_TYPE} eq "string" or 
	    $l->{DATA_TYPE} eq "nbt_string") {
		$var_name = get_pointer_to($var_name);
	}

	pidl "offset += dissect_$l->{DATA_TYPE}(tvb, offset, pinfo, tree, drep, hf_FIXME, NULL);";

	if (my $range = util::has_property($e, "range")) {
		$var_name = get_value_of($var_name);
		my ($low, $high) = split(/ /, $range, 2);
		if (($l->{DATA_TYPE} =~ /^uint/) and ($low eq "0")) {
		    pidl "if ($var_name > $high) {";
		} else {
		    pidl "if ($var_name < $low || $var_name > $high) {";
		}
		pidl "\treturn NT_STATUS_OK;";
		pidl "}";
	}
}

sub CalcNdrFlags($$$)
{
	my $l = shift;
	my $primitives = shift;
	my $deferred = shift;

	my $scalars = 0;
	my $buffers = 0;

	# Add NDR_SCALARS if this one is deferred 
	# and deferreds may be pushed
	$scalars = 1 if ($l->{IS_DEFERRED} and $deferred);

	# Add NDR_SCALARS if this one is not deferred and 
	# primitives may be pushed
	$scalars = 1 if (!$l->{IS_DEFERRED} and $primitives);
	
	# Add NDR_BUFFERS if this one contains deferred stuff
	# and deferreds may be pushed
	$buffers = 1 if ($l->{CONTAINS_DEFERRED} and $deferred);

	return "NDR_SCALARS|NDR_BUFFERS" if ($scalars and $buffers);
	return "NDR_SCALARS" if ($scalars);
	return "NDR_BUFFERS" if ($buffers);
	return undef;
}


sub ParseElementLevel
{
	my($e) = shift;
	my $l = shift;
	my $ndr = shift;
	my($var_name) = shift;
	my $env = shift;
	my $primitives = shift;
	my $deferred = shift;

	my $ndr_flags = CalcNdrFlags($l, $primitives, $deferred);

	# Only pull something if there's actually something to be pulled
	if (defined($ndr_flags)) {
		if ($l->{TYPE} eq "SUBCONTEXT") {
				($ndr,$var_name) = ParseSubcontextStart($e, $l, $ndr, $var_name, $ndr_flags, $env);
				ParseElementLevel($e,Ndr::GetNextLevel($e,$l), $ndr, $var_name, $env, $primitives, $deferred);
				ParseSubcontextEnd($e, $l);
		} elsif ($l->{TYPE} eq "ARRAY") {
			my $length = ParseArrayHeader($e, $l, $ndr, $var_name, $env); 
		} elsif ($l->{TYPE} eq "POINTER") {
			ParsePtr($e, $l, $ndr, $var_name);
		} elsif ($l->{TYPE} eq "SWITCH") {
			ParseSwitch($e, $l, $ndr, $var_name, $ndr_flags, $env);
		} elsif ($l->{TYPE} eq "DATA") {
			ParseData($e, $l, $ndr, $var_name, $ndr_flags);
		}
	}

	# add additional constructions
	if ($l->{TYPE} eq "POINTER" and $deferred) {
		if ($l->{POINTER_TYPE} ne "ref") {
			pidl "if ($var_name) {";
			indent;

			if ($l->{POINTER_TYPE} eq "relative") {
				pidl "struct ndr_pull_save _relative_save;";
				pidl "ndr_pull_save(ndr, &_relative_save);";
				pidl "NDR_CHECK(ndr_pull_relative_ptr2(ndr, $var_name));";
			}
		}

		$var_name = get_value_of($var_name);
		ParseElementLevel($e,Ndr::GetNextLevel($e,$l), $ndr, $var_name, $env, $primitives, $deferred);

		if ($l->{POINTER_TYPE} ne "ref") {
    		if ($l->{POINTER_TYPE} eq "relative") {
				pidl "ndr_pull_restore(ndr, &_relative_save);";
			}
			deindent;
			pidl "}";
		}
	} elsif ($l->{TYPE} eq "ARRAY") {
		my $length = ParseExpr($l->{LENGTH_IS}, $env);
		my $counter = "cntr_$e->{NAME}_$l->{LEVEL_INDEX}";

		$var_name = $var_name . "[$counter]";
		unless ($l->{NO_METADATA}) {
			$var_name = get_pointer_to($var_name);
		}

		if (($primitives and not $l->{IS_DEFERRED}) or ($deferred and $l->{IS_DEFERRED})) {
			pidl "for ($counter = 0; $counter < $length; $counter++) {";
			indent;
			ParseElementLevel($e,Ndr::GetNextLevel($e,$l), $ndr, $var_name, $env, 1, 0);
			deindent;
			pidl "}";
		}

		if ($deferred and Ndr::ContainsDeferred($e, $l)) {
			pidl "for ($counter = 0; $counter < $length; $counter++) {";
			indent;
			ParseElementLevel($e,Ndr::GetNextLevel($e,$l), $ndr, $var_name, $env, 0, 1);
			deindent;
			pidl "}";
		}
	} elsif ($l->{TYPE} eq "SWITCH") {
		ParseElementLevel($e,Ndr::GetNextLevel($e,$l), $ndr, $var_name, $env, $primitives, $deferred);
	}
}

#####################################################################
# parse scalars in a structure element - pull size
sub ParseElement($$$$$$)
{
	my($e) = shift;
	my $ndr = shift;
	my($var_prefix) = shift;
	my $env = shift;
	my $primitives = shift;
	my $deferred = shift;

	my $var_name = $var_prefix.$e->{NAME};

	$var_name = append_prefix($e, $var_name);

	return unless $primitives or ($deferred and Ndr::ContainsDeferred($e, $e->{LEVELS}[0]));

	start_flags($e);

	ParseElementLevel($e,$e->{LEVELS}[0],$ndr,$var_name,$env,$primitives,$deferred);

	end_flags($e);
}

#####################################################################
# parse a pointer in a struct element or function
sub ParsePtr($$$$)
{
	my($e) = shift;
	my $l = shift;
	my $ndr = shift;
	my($var_name) = shift;

	my $nl = Ndr::GetNextLevel($e, $l);
	my $next_is_array = ($nl->{TYPE} eq "ARRAY");

	if ($l->{LEVEL} eq "EMBEDDED") {
		pidl "dissect_ndr_embedded_pointer(FIXME);";
	} elsif ($l->{POINTER_TYPE} ne "ref") {
			pidl "dissect_ndr_toplevel_pointer(FIXME);";
	}

	#pidl "memset($var_name, 0, sizeof($var_name));";
	if ($l->{POINTER_TYPE} eq "relative") {
		pidl "ndr_pull_relative_ptr1($ndr, $var_name, _ptr_$e->{NAME});";
	}
}

$typefamily{ENUM} = {
	DECL => \&DeclEnum,
};

#####################################################################
# generate a pull function for an bitmap
sub ParseBitmap($$)
{
	my($bitmap) = shift;
	my $name = shift;
	my $type_fn = $bitmap->{BASE_TYPE};
	my($type_decl) = typelist::mapType($bitmap->{BASE_TYPE});

	pidl "$type_decl v_bitmap;";
	start_flags($bitmap);
	pidl "dissect_$type_fn(ndr, tree, hf, &v_bitmap);";
	
	pidl "{\n\tproto_tree *subtree = NULL;";
	pidl "";
	pidl "\tif (tree->proto_tree)\n\t\tsubtree = proto_item_add_subtree(tree->proto_tree->last_child, ett_$name);";
	pidl "";
	foreach my $e (@{$bitmap->{DATA}{ELEMENTS}}) {
	    $e =~ /^(.*?) \( (.*?) \)$/;
	    pidl "\tproto_tree_add_boolean(subtree, hf_${name}_$1, ndr->tvb, ndr->offset - sizeof(v_bitmap), sizeof(v_bitmap), v_bitmap);";
	}
	pidl "}";

	pidl "*r = v_bitmap;";

	end_flags($bitmap);
}

$typefamily{BITMAP} = {
	FN_BODY => \&ParseBitmap,
};

#####################################################################
# parse a struct - pull side
sub ParseStruct($$)
{
	my($struct) = shift;
	my $name = shift;
	my $conform_e;

	return unless defined $struct->{ELEMENTS};

	my $env = GenerateStructEnv($struct);

	# see if the structure contains a conformant array. If it
	# does, then it must be the last element of the structure, and
	# we need to pull the conformant length early, as it fits on
	# the wire before the structure (and even before the structure
	# alignment)
	$conform_e = $struct->{SURROUNDING_ELEMENT};

	# declare any internal pointers we need
	foreach my $e (@{$struct->{ELEMENTS}}) {
		foreach my $l (@{$e->{LEVELS}}) {
			if ($l->{TYPE} eq "POINTER" and not ($l->{POINTER_TYPE} eq "ref" and $l->{LEVEL} eq "TOP")) {
				pidl "uint32_t _ptr_$e->{NAME};";
				last;
			}
		}
	}

	start_flags($struct);

	pidl "if (ndr_flags & NDR_SCALARS) {";
	indent;

	if (defined $conform_e) {
		ParseArrayPreceding($conform_e, $conform_e->{LEVELS}[0], "r->$conform_e->{NAME}");
	}

	pidl "ndr_pull_align(ndr, $struct->{ALIGN});";

	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElement($e, "ndr", "r->", $env, 1, 0);
	}	
	deindent;
	pidl "}";

	pidl "if (ndr_flags & NDR_BUFFERS) {";
	indent;
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElement($e, "ndr", "r->", $env, 0, 0);
	}

	pidl "proto_item_set_end(tree->proto_tree, ndr->tvb, ndr->offset);";
	deindent;
	pidl "}";

	end_flags($struct);
}

$typefamily{STRUCT} = {
	FN_BODY => \&ParseStruct,
};

#####################################################################
# parse a union - pull side
sub ParseUnion($$$)
{
	my $e = shift;
	my $name = shift;
	my $have_default = 0;
	my $switch_type = $e->{SWITCH_TYPE};

	pidl "int level;";
	if (defined($switch_type)) {
		if (typelist::typeIs($switch_type, "ENUM")) {
			$switch_type = typelist::enum_type_fn(typelist::getType($switch_type));
		}
		pidl typelist::mapType($switch_type) . " _level;";
	}

	start_flags($e);

	pidl "level = ndr_pull_get_switch_value(ndr, r);";

	pidl "if (ndr_flags & NDR_SCALARS) {";
	indent;

	if (defined($switch_type)) {
		pidl "ndr_pull_$switch_type(ndr, tree, hf_${name}, &_level);";
		pidl "if (_level != level) {"; 
		pidl "\treturn NT_STATUS_OK;";
		pidl "}";
	}

#	my $align = union_alignment($e);
#	pidl "\tndr_pull_align(ndr, $align);\n";

	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if ($el->{CASE} eq "default") {
			$have_default = 1;
		} 
		pidl "$el->{CASE}: {";

		if ($el->{TYPE} ne "EMPTY") {
			indent;
			foreach my $l (@{$el->{LEVELS}}) {
				if ($l->{TYPE} eq "POINTER" and not ($l->{POINTER_TYPE} eq "ref" and $l->{LEVEL} eq "TOP")) {
					pidl "uint32_t _ptr_$el->{NAME};";
					last;
				}
			}
			ParseElement($el, "ndr", "r->", {}, 1, 0);
			deindent;
		}
		pidl "break; }";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn NT_STATUS_OK;";
	}
	deindent;
	pidl "}";
	deindent;
	pidl "}";
	pidl "if (ndr_flags & NDR_BUFFERS) {";
	indent;
	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		pidl "$el->{CASE}:";
		if ($el->{TYPE} ne "EMPTY") {
			indent;
			ParseElement($el, "ndr", "r->", {}, 0, 1);
			deindent;
		}
		pidl "break;";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn NT_STATUS_OK;";
	}
	deindent;
	pidl "}";
	pidl "proto_item_set_end(tree->proto_tree, ndr->tvb, ndr->offset);";
	deindent;
	pidl "}";
	end_flags($e);
}

$typefamily{UNION} = {
	FN_BODY => \&ParseUnion,
};

#####################################################################
# parse an array
sub ParseArrayHeader($$$$$)
{
	my $e = shift;
	my $l = shift;
	my $ndr = shift;
	my $var_name = shift;
	my $env = shift;

	unless ($l->{NO_METADATA}) {
		$var_name = get_pointer_to($var_name);
	}

	# $var_name contains the name of the first argument here

	my $length = ParseExpr($l->{SIZE_IS}, $env);
	my $size = $length;

	if ($l->{IS_CONFORMANT}) {
		$length = $size = "ndr_get_array_size($ndr, " . get_pointer_to($var_name) . ")";
	}

	# if this is a conformant array then we use that size to allocate, and make sure
	# we allocate enough to pull the elements
	if (!$l->{IS_SURROUNDING}) {
		ParseArrayPreceding($e, $l, $var_name);
	}


	if ($l->{IS_VARYING}) {
		pidl "NDR_CHECK(ndr_pull_array_length($ndr, " . get_pointer_to($var_name) . "));";
		$length = "ndr_get_array_length($ndr, " . get_pointer_to($var_name) .")";
	}

	check_null_pointer($length);

	if ($length ne $size) {
		pidl "if ($length > $size) {";
		indent;
		pidl "return ndr_pull_error($ndr, NDR_ERR_ARRAY_SIZE, \"Bad array size %u should exceed array length %u\", $size, $length);";
		deindent;
		pidl "}";
	}

	if ($l->{IS_CONFORMANT}) {
		my $size = ParseExpr($l->{SIZE_IS}, $env);
		check_null_pointer($size);
		pidl "NDR_CHECK(ndr_check_array_size(ndr, (void*)" . get_pointer_to($var_name) . ", $size));";
	}

	if ($l->{IS_VARYING}) {
		my $length = ParseExpr($l->{LENGTH_IS}, $env);
		check_null_pointer($length);
		pidl "NDR_CHECK(ndr_check_array_length(ndr, (void*)" . get_pointer_to($var_name) . ", $length));";
	}

	return $length;
}
	
#####################################################################
# parse a typedef - pull side
sub ParseTypedef($)
{
	my($e) = shift;

	return unless (defined ($typefamily{$e->{DATA}->{TYPE}}));

	pidl fn_prefix($e) . "int dissect_$e->{NAME}(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index, guint32 param)";

	pidl "{";
	indent;
	$typefamily{$e->{DATA}->{TYPE}}->{FN_BODY}->($e->{DATA}, $e->{NAME});
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# parse a function
sub ParseFunctionRqst($)
{ 
	my($fn) = shift;

	my $env = GenerateFunctionEnv($fn);

	# request function
	pidl "static int dissect_$fn->{NAME}_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)";
	pidl "{";
	indent;

	pidl "struct pidl_pull *ndr = pidl_pull_init(tvb, offset, pinfo, drep);";

	# declare any internal pointers we need
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep (/in/, @{$e->{DIRECTIONS}}));
		foreach my $l (@{$e->{LEVELS}}) {
			if ($l->{TYPE} eq "POINTER" and 
				not ($l->{POINTER_TYPE} eq "ref" and 
				$l->{LEVEL} eq "TOP")) {
				pidl "uint32_t _ptr_$e->{NAME};"; 
				last;
			}
		}
	}

	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep(/in/, @{$e->{DIRECTION}}));
		ParseElement($e, "ndr", "r->in.", $env, 1, 1);
	}

	pidl "return offset;";
	deindent;
	pidl "}";
	pidl "";
}

sub ParseFunctionResp($)
{ 
	my($fn) = shift;

	my $env = GenerateFunctionEnv($fn);

	# response function
	pidl "static int dissect_$fn->{NAME}_resp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)";
	pidl "{";
	indent;

	pidl "struct pidl_pull *ndr = pidl_pull_init(tvb, offset, pinfo, drep);";

	# declare any internal pointers we need
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep (/out/, @{$e->{DIRECTIONS}}));
		foreach my $l (@{$e->{LEVELS}}) {
			if ($l->{TYPE} eq "POINTER" and 
				not ($l->{POINTER_TYPE} eq "ref" and 
				$l->{LEVEL} eq "TOP")) {
				pidl "uint32_t _ptr_$e->{NAME};"; 
				last;
			}
		}
	}

	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless grep(/out/, @{$e->{DIRECTION}});
		ParseElement($e, "ndr", "r->out.", $env, 1, 1);
	}

	if ($fn->{RETURN_TYPE}) {
		pidl "dissect_$fn->{RETURN_TYPE}(ndr, tree, hf_$fn->{NAME}_result, drep);";
	}

	pidl "return offset;";
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# produce a function call table
sub FunctionTable($)
{
	my($interface) = shift;

	pidl "static dcerpc_sub_dissector dcerpc_dissectors[] = {";
	my $num = 0;
	foreach my $d (@{$interface->{FUNCTIONS}}) {
	    # Strip interface name from function name, if present
	    my($n) = $d->{NAME};
	    $n = substr($d->{NAME}, length($interface->{NAME}) + 1),
	        if $interface->{NAME} eq substr($d->{NAME}, 0, length($interface->{NAME}));
	    pidl "\t{ $num, \"$n\",";
	    pidl "\t\tdissect_$d->{NAME}_rqst,";
	    pidl "\t\tdissect_$d->{NAME}_resp },";
	    $num++;
	}
	pidl "};\n";
}

#####################################################################
# parse the interface definitions
sub ParseInterface($$)
{
	my($interface) = shift;
	my $needed = shift;

	# Typedefs
	foreach my $d (@{$interface->{TYPEDEFS}}) {
		($needed->{"pull_$d->{NAME}"}) && ParseTypedef($d);
		# Make sure we don't generate a function twice...
		$needed->{"pull_$d->{NAME}"} = 0;
	}

	# Functions
	foreach my $d (@{$interface->{FUNCTIONS}}) {
		if ($needed->{"pull_$d->{NAME}"}) {
			ParseFunctionRqst($d);
			ParseFunctionResp($d);
		}

		# Make sure we don't generate a function twice...
		$needed->{"pull_$d->{NAME}"} = 0;
	}
}

#####################################################################
# generate code to parse an enum
sub DeclEnum($$)
{
    my ($e) = shift;
	my $n = shift;

    pidl "static const value_string $n\_vals[] =";
    pidl "{";

    foreach my $x (@{$e->{ELEMENTS}}) {
	$x =~ /([^=]*)=(.*)/;
	pidl "\t{ $1, \"$1\" },";
    }
    
    pidl "};\n";
}

sub DeclInterface($$)
{
	my($interface) = shift;
	my $needed = shift;

	# Typedefs
	foreach my $d (@{$interface->{TYPEDEFS}}) {
		($needed->{"pull_$d->{NAME}"}) && DeclTypedef($d);

		# Make sure we don't generate a function twice...
		$needed->{"pull_$d->{NAME}"} = 0;
	}
}

sub DeclTypedef($)
{
	my $e = shift;

	if (defined($typefamily{$e->{DATA}->{TYPE}}->{DECL})) {
		$typefamily{$e->{DATA}->{TYPE}}->{DECL}->($e->{DATA}, $e->{NAME});
	}
}

sub RegisterInterface($$)
{
	my $x = shift;
	my $needed = shift;

	pidl "void proto_register_dcerpc_pidl_$x->{NAME}(void)";
	pidl "{";
	indent;
	
	pidl "static hf_register_info hf[] = {";
	pidl "{ &hf_ptr, { \"Pointer\", \"$x->{NAME}.ptr\", FT_UINT32, BASE_HEX, NULL, 0x0, \"Pointer\", HFILL }},";
	
	foreach my $x (sort keys(%{$needed})) {
	    next, if !($x =~ /^hf_/);
	    pidl "{ &$x,";
	    $needed->{$x}->{strings} = "NULL", if !defined($needed->{$x}->{strings});
	    $needed->{$x}->{bitmask} = "0", if !defined($needed->{$x}->{bitmask});
	    pidl "  { \"$needed->{$x}->{name}\", \"$x\", $needed->{$x}->{ft}, $needed->{$x}->{base}, $needed->{$x}->{strings}, $needed->{$x}->{bitmask}, \"$x\", HFILL }},";
	}
	
	pidl "};\n";
	
	pidl "static gint *ett[] = {";
	indent;
	foreach my $x (sort keys(%{$needed})) {
	    pidl "&$x,", if $x =~ /^ett_/;
	}
	deindent;

	pidl "};\n";

	if (defined($x->{UUID})) {
	    # These can be changed to non-pidl names if the old dissectors
	    # in epan/dissctors are deleted.
    
	    my $name = "\"" . uc($x->{NAME}) . " (pidl)\"";
		if (util::has_property($x, "helpstring")) {
			$name = $x->{PROPERTIES}->{helpstring};
		}
	    my $short_name = "pidl_$x->{NAME}";
	    my $filter_name = "pidl_$x->{NAME}";
    
	    pidl "proto_dcerpc_pidl_$x->{NAME} = proto_register_protocol($name, \"$short_name\", \"$filter_name\");";
	    
	    pidl "proto_register_field_array(proto_dcerpc_pidl_$x->{NAME}, hf, array_length (hf));";
	    pidl "proto_register_subtree_array(ett, array_length(ett));";
	} else {
	    pidl "int proto_dcerpc;";
	    pidl "proto_dcerpc = proto_get_id_by_filter_name(\"dcerpc\");";
	    pidl "proto_register_field_array(proto_dcerpc, hf, array_length(hf));";
	    pidl "proto_register_subtree_array(ett, array_length(ett));";
	}
	    
	deindent;
	pidl "}\n";
}

sub RegisterInterfaceHandoff($)
{
	my $x = shift;
	pidl "void proto_reg_handoff_dcerpc_pidl_$x->{NAME}(void)";
	pidl "{";
	indent;
	pidl "dcerpc_init_uuid(proto_dcerpc_pidl_$x->{NAME}, ett_dcerpc_$x->{NAME},";
	pidl "\t&uuid_dcerpc_$x->{NAME}, ver_dcerpc_$x->{NAME},";
	pidl "\tdcerpc_dissectors, hf_$x->{NAME}_opnum);";
	deindent;
	pidl "}";
}

sub ProcessInterface($)
{
	my $x = shift;
	my $needed = NeededInterface($x);

	# Required global declarations
	DeclInterface($x, $needed);

	foreach my $y (sort keys(%{$needed})) {
	    pidl "static int $y = -1;", if $y =~ /^hf_/;
	}
	pidl "";

	foreach my $y (sort keys(%{$needed})) {
	    pidl "static gint $y = -1;", if $y =~ /^ett_/;
	}
	pidl "";

	pidl "int proto_dcerpc_pidl_$x->{NAME} = -1;\n";
	
	if (defined($x->{UUID})) {
		my $if_uuid = $x->{UUID};
	    
	    pidl "static e_uuid_t uuid_dcerpc_$x->{NAME} = {";
	    pidl "\t0x" . substr($if_uuid, 1, 8) 
  		. ", 0x" . substr($if_uuid, 10, 4)
	    . ", 0x" . substr($if_uuid, 15, 4) . ",";
	    pidl "\t{ 0x" . substr($if_uuid, 20, 2) 
		. ", 0x" . substr($if_uuid, 22, 2)
	    . ", 0x" . substr($if_uuid, 25, 2)
	    . ", 0x" . substr($if_uuid, 27, 2)
	    . ", 0x" . substr($if_uuid, 29, 2)
	    . ", 0x" . substr($if_uuid, 31, 2)
	    . ", 0x" . substr($if_uuid, 33, 2)
	    . ", 0x" . substr($if_uuid, 35, 2) . " }";
	    pidl "};\n";
	
	    pidl "static guint16 ver_dcerpc_$x->{NAME} = $x->{VERSION};";
	}

	# dissect_* functions
	ParseInterface($x, $needed);

	# Function call tables
	FunctionTable($x);

	RegisterInterface($x, $needed);
	RegisterInterfaceHandoff($x);
}

#####################################################################
# parse a parsed IDL structure back into an IDL file
sub Parse($$$)
{
	my($ndr) = shift;
	my $module = shift;
	my($filename) = shift;

	$tabs = "";
	my $h_filename = $filename;
	$res = "";

	if ($h_filename =~ /(.*)\.c/) {
		$h_filename = "$1.h";
	}

	pidl "/* parser auto-generated by pidl */";
	pidl "#include \"packet-dcerpc.h\"";
	pidl "#include \"$h_filename\"";
	pidl "";
	pidl "static int hf_ptr = -1;";
	pidl "static int hf_array_size = -1;";
	pidl "";

#	print keys %{$needed->{hf_atsvc_JobGetInfo_result}}, "\n";

	# Ethereal protocol registration

	ProcessInterface($_) foreach (@$ndr);
    
	return $res;
}

1;
