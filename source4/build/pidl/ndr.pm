###################################################
# Samba4 NDR parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# Copyright jelmer@samba.org 2004-2005
# released under the GNU GPL

package NdrParser;

use strict;
use needed;

# list of known types
our %typedefs;
our %typefamily;

sub RegisterPrimitives()
{
	my %type_alignments = 
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
     "NTTIME"         => 4,
     "NTTIME_1sec"    => 4,
     "time_t"         => 4,
     "DATA_BLOB"      => 4,
     "error_status_t" => 4,
     "WERROR"         => 4,
     "boolean32"      => 4,
     "unsigned32"     => 4,
     "ipv4address"    => 4,
     "hyper"          => 8,
     "NTTIME_hyper"   => 8
     );

	foreach my $k (keys %type_alignments) {
		$typedefs{$k} = {
			NAME => $k,
			TYPE => "TYPEDEF",
			DATA => {
				TYPE => "SCALAR",
				ALIGN => $type_alignments{$k}
			}
		};
	}
}

sub is_scalar_type($)
{
    my $type = shift;

	if (my $dt = $typedefs{$type}->{DATA}->{TYPE}) {
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

	return undef;
}

# determine if an element needs a reference pointer on the wire
# in its NDR representation
sub need_wire_pointer($)
{
	my $e = shift;
	my $pt;
	
	return 0 unless ($pt = pointer_type($e));

	if ($pt ne "ref") {
		return 1;
	} else {
		return 0;
	}
}

# determine if an element is a pure scalar. pure scalars do not
# have a "buffers" section in NDR
sub is_pure_scalar($)
{
	my $e = shift;
	if (util::has_property($e, "ref")) {
		return 1;
	}
	if (is_scalar_type($e->{TYPE}) && 
	    !$e->{POINTERS} && 
	    !util::array_size($e)) {
		return 1;
	}
	return 0;
}

# see if a variable needs to be allocated by the NDR subsystem on pull
sub need_alloc($)
{
	my $e = shift;

	if (util::has_property($e, "ref")) {
		return 0;
	}

	if ($e->{POINTERS} || util::array_size($e)) {
		return 1;
	}

	return 0;
}


# determine the C prefix used to refer to a variable when passing to a push
# function. This will be '*' for pointers to scalar types, '' for scalar
# types and normal pointers and '&' for pass-by-reference structures
sub c_push_prefix($)
{
	my $e = shift;

	if ($e->{TYPE} =~ "string") {
		return "";
	}

	if (is_scalar_type($e->{TYPE}) &&
	    $e->{POINTERS}) {
		return "*";
	}
	if (!is_scalar_type($e->{TYPE}) &&
	    !$e->{POINTERS} &&
	    !util::array_size($e)) {
		return "&";
	}
	return "";
}


# determine the C prefix used to refer to a variable when passing to a pull
# return '&' or ''
sub c_pull_prefix($)
{
	my $e = shift;

	if (!$e->{POINTERS} && !util::array_size($e)) {
		return "&";
	}

	if ($e->{TYPE} =~ "string") {
		return "&";
	}

	return "";
}
my $res = "";
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

sub indent
{
	$tabs .= "\t";
}

sub deindent
{
	$tabs = substr($tabs, 0, -1);
}

###################################
# find a sibling var in a structure
sub find_sibling($$)
{
	my($e) = shift;
	my($name) = shift;
	my($fn) = $e->{PARENT};

	if ($name =~ /\*(.*)/) {
		$name = $1;
	}

	if ($fn->{TYPE} eq "FUNCTION") {
		for my $e2 (@{$fn->{ELEMENTS}}) {
			if ($e2->{NAME} eq $name) {
				return $e2;
			}
		}
	}

	for my $e2 (@{$fn->{ELEMENTS}}) {
		if ($e2->{NAME} eq $name) {
			return $e2;
		}
	}
	die "invalid sibling '$name'";
}

####################################################################
# work out the name of a size_is() variable
sub ParseExpr($$$)
{
	my($e) = shift;
	my($size) = shift;
	my($var_prefix) = shift;

	my($fn) = $e->{PARENT};

	if (util::is_constant($size)) {
		return $size;
	}

	if ($size =~ /ndr->|\(/) {
		return $size;
	}

	my $prefix = "";

	if ($size =~ /\*(.*)/) {
		$size = $1;
		$prefix = "*";
	}

	if ($fn->{TYPE} ne "FUNCTION") {
		return $prefix . "r->$size";
	}

	my $e2 = find_sibling($e, $size);

	if (util::has_property($e2, "in") && util::has_property($e2, "out")) {
		return $prefix . "$var_prefix$size";
	}
	if (util::has_property($e2, "in")) {
		return $prefix . "r->in.$size";
	}
	if (util::has_property($e2, "out")) {
		return $prefix . "r->out.$size";
	}

	die "invalid variable in $size for element $e->{NAME} in $fn->{NAME}\n";
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
	if ($fn->{TYPE} eq "TYPEDEF") {
		if (util::has_property($fn, "public")) {
			return "";
		}
	}

	if ($fn->{TYPE} eq "FUNCTION") {
		if (util::has_property($fn, "public")) {
			return "";
		}
	}
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
	}
}

#####################################################################
# work out the correct alignment for a structure or union
sub find_largest_alignment($)
{
	my $s = shift;

	my $align = 1;
	for my $e (@{$s->{ELEMENTS}}) {
		my $a = 1;

		if (need_wire_pointer($e)) {
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

	unless (defined($typedefs{$e}) && defined($typedefs{$e}->{DATA}->{TYPE})) {
	    # it must be an external type - all we can do is guess 
		# print "Warning: assuming alignment of unknown type '$e' is 4\n";
	    return 4;
	}

	my $dt = $typedefs{$e}->{DATA};

	return $dt->{ALIGN} if ($dt->{ALIGN});
	return $typefamily{$dt->{TYPE}}->{ALIGN}($dt);
}

#####################################################################
# parse an array - push side
sub ParseArrayPush($$$)
{
	my $e = shift;
	my $var_prefix = shift;
	my $ndr_flags = shift;

	my $size = ParseExpr($e, util::array_size($e), $var_prefix);

	if (defined $e->{CONFORMANT_SIZE}) {
		# the conformant size has already been pushed
	} elsif (!util::is_inline_array($e)) {
		# we need to emit the array size
		pidl "NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, $size));";
	}

	if (my $length = util::has_property($e, "length_is")) {
		$length = ParseExpr($e, $length, $var_prefix);
		pidl "NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));";
		pidl "NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, $length));";
		$size = $length;
	}

	if (is_scalar_type($e->{TYPE})) {
		pidl "NDR_CHECK(ndr_push_array_$e->{TYPE}(ndr, $ndr_flags, $var_prefix$e->{NAME}, $size));";
	} else {
		pidl "NDR_CHECK(ndr_push_array(ndr, $ndr_flags, $var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_push_flags_fn_t)ndr_push_$e->{TYPE}));";
	}
}

#####################################################################
# print an array
sub ParseArrayPrint($$)
{
	my $e = shift;
	my $var_prefix = shift;
	my $size = ParseExpr($e, util::array_size($e), $var_prefix);
	my $length = util::has_property($e, "length_is");

	if (defined $length) {
		$size = ParseExpr($e, $length, $var_prefix);
	}

	if (is_scalar_type($e->{TYPE})) {
		pidl "ndr_print_array_$e->{TYPE}(ndr, \"$e->{NAME}\", $var_prefix$e->{NAME}, $size);";
	} else {
		pidl "ndr_print_array(ndr, \"$e->{NAME}\", $var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_print_fn_t)ndr_print_$e->{TYPE});";
	}
}

#####################################################################
# check the size_is and length_is constraints
sub CheckArraySizes($$)
{
	my $e = shift;
	my $var_prefix = shift;

	if (!defined $e->{CONFORMANT_SIZE} && 
	    util::has_property($e, "size_is")) {
		my $size = ParseExpr($e, util::array_size($e), $var_prefix);
		pidl "if ($var_prefix$e->{NAME}) {";
		indent;
		check_null_pointer($size);
		pidl "NDR_CHECK(ndr_check_array_size(ndr, (void*)&$var_prefix$e->{NAME}, $size));";
		deindent;
		pidl "}";
	}

	if (my $length = util::has_property($e, "length_is")) {
		$length = ParseExpr($e, $length, $var_prefix);
		pidl "if ($var_prefix$e->{NAME}) {";
		indent;
		check_null_pointer($length);
		pidl "NDR_CHECK(ndr_check_array_length(ndr, (void*)&$var_prefix$e->{NAME}, $length));";
		deindent;
		pidl "}";
	}
}

#####################################################################
# parse an array - pull side
sub ParseArrayPull($$$)
{
	my $e = shift;
	my $var_prefix = shift;
	my $ndr_flags = shift;

	my $size = ParseExpr($e, util::array_size($e), $var_prefix);
	my $alloc_size = $size;

	# if this is a conformant array then we use that size to allocate, and make sure
	# we allocate enough to pull the elements
	if (defined $e->{CONFORMANT_SIZE}) {
		$alloc_size = $e->{CONFORMANT_SIZE};
		check_null_pointer($size);
		pidl "if ($size > $alloc_size) {";
		indent;
		pidl "return ndr_pull_error(ndr, NDR_ERR_CONFORMANT_SIZE, \"Bad conformant size %u should be %u\", $alloc_size, $size);";
		deindent;
		pidl "}";
	} elsif (!util::is_inline_array($e)) {
		if ($var_prefix =~ /^r->out/ && $size =~ /^\*r->in/) {
			my $size2 = substr($size, 1);
			pidl "if (ndr->flags & LIBNDR_FLAG_REF_ALLOC) {	NDR_ALLOC(ndr, $size2); }";
		}

		# non fixed arrays encode the size just before the array
		pidl "NDR_CHECK(ndr_pull_array_size(ndr, &$var_prefix$e->{NAME}));";
		$alloc_size = "ndr_get_array_size(ndr, &$var_prefix$e->{NAME})";
	}

	if ((need_alloc($e) && !util::is_fixed_array($e)) ||
	    ($var_prefix eq "r->in." && util::has_property($e, "ref"))) {
		if (!util::is_inline_array($e) || $ndr_flags eq "NDR_SCALARS") {
			pidl "NDR_ALLOC_N(ndr, $var_prefix$e->{NAME}, $alloc_size);";
		}
	}

	if (($var_prefix eq "r->out." && util::has_property($e, "ref"))) {
		if (!util::is_inline_array($e) || $ndr_flags eq "NDR_SCALARS") {
			pidl "if (ndr->flags & LIBNDR_FLAG_REF_ALLOC) {";
			indent;
			pidl "NDR_ALLOC_N(ndr, $var_prefix$e->{NAME}, $alloc_size);";
			deindent;
			pidl "}";
		}
	}

	if (my $length = util::has_property($e, "length_is")) {
		pidl "NDR_CHECK(ndr_pull_array_length(ndr, &$var_prefix$e->{NAME}));";
		$size = "ndr_get_array_length(ndr, &$var_prefix$e->{NAME})";
	}

	check_null_pointer($size);
	if (is_scalar_type($e->{TYPE})) {
		pidl "NDR_CHECK(ndr_pull_array_$e->{TYPE}(ndr, $ndr_flags, $var_prefix$e->{NAME}, $size));";
	} else {
		pidl "NDR_CHECK(ndr_pull_array(ndr, $ndr_flags, (void **)$var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_pull_flags_fn_t)ndr_pull_$e->{TYPE}));";
	}
}

#####################################################################
# parse scalars in a structure element
sub ParseElementPushScalar($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $cprefix = c_push_prefix($e);
	my $sub_size = util::has_property($e, "subcontext");

	start_flags($e);

	if (my $value = util::has_property($e, "value")) {
		pidl "$cprefix$var_prefix$e->{NAME} = $value;";
	}

	if (util::has_property($e, "relative")) {
		pidl "NDR_CHECK(ndr_push_relative_ptr1(ndr, $var_prefix$e->{NAME}));";
	} elsif (util::is_inline_array($e)) {
		ParseArrayPush($e, "r->", "NDR_SCALARS");
	} elsif (need_wire_pointer($e)) {
		pidl "NDR_CHECK(ndr_push_unique_ptr(ndr, $var_prefix$e->{NAME}));";
	} elsif (need_alloc($e)) {
		# no scalar component
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPushSwitch($e, $var_prefix, $ndr_flags, $switch);
	} elsif (defined $sub_size) {
		pidl "NDR_CHECK(ndr_push_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_push_flags_fn_t) ndr_push_$e->{TYPE}));";
	} else {
		pidl "NDR_CHECK(ndr_push_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));";
	}

	end_flags($e);
}

#####################################################################
# print scalars in a structure element
sub ParseElementPrintScalar($$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my $cprefix = c_push_prefix($e);

	if (util::has_property($e, "noprint")) {
		return;
	}

	if (my $value = util::has_property($e, "value")) {
		pidl "if (ndr->flags & LIBNDR_PRINT_SET_VALUES) {";
		indent;
		pidl "$cprefix$var_prefix$e->{NAME} = $value;";
		deindent;
		pidl "}";
	}

	if (util::is_fixed_array($e)) {
		ParseElementPrintBuffer($e, $var_prefix);
	} elsif ($e->{POINTERS} || util::array_size($e)) {
		pidl "ndr_print_ptr(ndr, \"$e->{NAME}\", $var_prefix$e->{NAME});";
		pidl "ndr->depth++;";
		ParseElementPrintBuffer($e, $var_prefix);
		pidl "ndr->depth--;";
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPrintSwitch($e, $var_prefix, $switch);
	} else {
		pidl "ndr_print_$e->{TYPE}(ndr, \"$e->{NAME}\", $cprefix$var_prefix$e->{NAME});";
	}
}

#####################################################################
# parse scalars in a structure element - pull size
sub ParseElementPullSwitch($$$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $switch = shift;
	my $switch_var = ParseExpr($e, $switch, $var_prefix);

	my $cprefix = c_pull_prefix($e);

	my $utype = $typedefs{$e->{TYPE}};

	check_null_pointer($switch_var);

	if (!defined $utype ||
	    !util::has_property($utype, "nodiscriminant")) {
		my $e2 = find_sibling($e, $switch);
		my $type_decl = util::map_type($e2->{TYPE});
		pidl "if (($ndr_flags) & NDR_SCALARS) {";
		indent;
		if ($typedefs{$e2->{TYPE}}->{DATA}->{TYPE} eq "ENUM") {
			$type_decl = util::enum_type_decl($e2);
		} elsif ($typedefs{$e2->{TYPE}}->{DATA}->{TYPE} eq "BITMAP") {
			$type_decl = util::bitmap_type_decl($e2);
		}
		pidl "$type_decl _level;";
		pidl "NDR_CHECK(ndr_pull_$e2->{TYPE}(ndr, NDR_SCALARS, &_level));";
		if ($switch_var =~ /r->in/) {
			pidl "if (!(ndr->flags & LIBNDR_FLAG_REF_ALLOC) && _level != $switch_var) {";
			indent;
		} else {
			pidl "if (_level != $switch_var) {"; 
			indent;
		}
		pidl "return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value %u in $e->{NAME}\", _level);";
		deindent;
		if ($switch_var =~ /r->/) {
			pidl "} else { $switch_var = _level; }";
		} else {
			pidl "}";
		}
		deindent;
		pidl "}";
	}

	my $sub_size = util::has_property($e, "subcontext");
	if (defined $sub_size) {
		pidl "if (($ndr_flags) & NDR_SCALARS) {";
		indent;
		pidl "NDR_CHECK(ndr_pull_subcontext_union_fn(ndr, $sub_size, $switch_var, $cprefix$var_prefix$e->{NAME}, (ndr_pull_union_fn_t) ndr_pull_$e->{TYPE}));";
		deindent;
		pidl "}";
	} else {
		pidl "NDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $ndr_flags, $switch_var, $cprefix$var_prefix$e->{NAME}));";
	}


}

#####################################################################
# push switch element
sub ParseElementPushSwitch($$$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $switch = shift;
	my $switch_var = ParseExpr($e, $switch, $var_prefix);
	my $cprefix = c_push_prefix($e);

	check_null_pointer($switch_var);

	my $utype = $typedefs{$e->{TYPE}};
	if (!defined $utype ||
	    !util::has_property($utype, "nodiscriminant")) {
		my $e2 = find_sibling($e, $switch);
		pidl "if (($ndr_flags) & NDR_SCALARS) {";
		indent;
		pidl "NDR_CHECK(ndr_push_$e2->{TYPE}(ndr, NDR_SCALARS, $switch_var));";
		deindent;
		pidl "}";
	}

	my $sub_size = util::has_property($e, "subcontext");
	if (defined $sub_size) {
		pidl "if(($ndr_flags) & NDR_SCALARS) {";
		indent;
		pidl "NDR_CHECK(ndr_push_subcontext_union_fn(ndr, $sub_size, $switch_var, $cprefix$var_prefix$e->{NAME}, (ndr_push_union_fn_t) ndr_push_$e->{TYPE}));";
		deindent;
		pidl "}";
	} else {
		pidl "NDR_CHECK(ndr_push_$e->{TYPE}(ndr, $ndr_flags, $switch_var, $cprefix$var_prefix$e->{NAME}));";
	}
}

#####################################################################
# print scalars in a structure element 
sub ParseElementPrintSwitch($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my $switch = shift;
	my $switch_var = ParseExpr($e, $switch, $var_prefix);
	my $cprefix = c_push_prefix($e);

	check_null_pointer_void($switch_var);

	pidl "ndr_print_$e->{TYPE}(ndr, \"$e->{NAME}\", $switch_var, $cprefix$var_prefix$e->{NAME});";
}


#####################################################################
# parse scalars in a structure element - pull size
sub ParseElementPullScalar($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $cprefix = c_pull_prefix($e);
	my $sub_size = util::has_property($e, "subcontext");

	start_flags($e);

	if (util::is_inline_array($e)) {
		ParseArrayPull($e, "r->", "NDR_SCALARS");
	} elsif (need_wire_pointer($e)) {
		pidl "NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_$e->{NAME}));";
		pidl "if (_ptr_$e->{NAME}) {";
		indent;
		pidl "NDR_ALLOC(ndr, $var_prefix$e->{NAME});";
		if (util::has_property($e, "relative")) {
			pidl "NDR_CHECK(ndr_pull_relative_ptr1(ndr, $var_prefix$e->{NAME}, _ptr_$e->{NAME}));";
		}
		deindent;
		pidl "} else {";
		indent;
		pidl "$var_prefix$e->{NAME} = NULL;";
		deindent;
		pidl "}";
	} elsif (need_alloc($e)) {
		# no scalar component
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPullSwitch($e, $var_prefix, $ndr_flags, $switch);
	} elsif (defined $sub_size) {
		pidl "NDR_CHECK(ndr_pull_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_flags_fn_t) ndr_pull_$e->{TYPE}));";
	} else {
		pidl "NDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));";
	}
	if (my $range = util::has_property($e, "range")) {
		my ($low, $high) = split(/ /, $range, 2);
		pidl "if ($var_prefix$e->{NAME} < $low || $var_prefix$e->{NAME} > $high) {";
		indent;
		pidl "return ndr_pull_error(ndr, NDR_ERR_RANGE, \"value out of range\");";
		deindent;
		pidl "}";
	}

	end_flags($e);
}

#####################################################################
# parse buffers in a structure element
sub ParseElementPushBuffer($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $cprefix = c_push_prefix($e);
	my $sub_size = util::has_property($e, "subcontext");

	if (is_pure_scalar($e)) {
		return;
	}

	start_flags($e);

	if (need_wire_pointer($e)) {
		pidl "if ($var_prefix$e->{NAME}) {";
		indent;
		if (util::has_property($e, "relative")) {
			pidl "NDR_CHECK(ndr_push_relative_ptr2(ndr, $var_prefix$e->{NAME}));";
		}
	}
	    
	if (util::is_inline_array($e)) {
		ParseArrayPush($e, "r->", "NDR_BUFFERS");
	} elsif (util::array_size($e)) {
		ParseArrayPush($e, "r->", "NDR_SCALARS|NDR_BUFFERS");
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		if ($e->{POINTERS}) {
			ParseElementPushSwitch($e, $var_prefix, "NDR_BUFFERS|NDR_SCALARS", $switch);
		} else {
			ParseElementPushSwitch($e, $var_prefix, "NDR_BUFFERS", $switch);
		}
	} elsif (defined $sub_size) {
		if ($e->{POINTERS}) {
			pidl "NDR_CHECK(ndr_push_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_push_flags_fn_t) ndr_push_$e->{TYPE}));";
		}
	} elsif ($e->{POINTERS}) {
		pidl "NDR_CHECK(ndr_push_$e->{TYPE}(ndr, NDR_SCALARS|NDR_BUFFERS, $cprefix$var_prefix$e->{NAME}));";
	} else {
		pidl "NDR_CHECK(ndr_push_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));";
	}

	if (need_wire_pointer($e)) {
		deindent;
		pidl "}";
	}	

	end_flags($e);
}

#####################################################################
# print buffers in a structure element
sub ParseElementPrintBuffer($$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my $cprefix = c_push_prefix($e);

	if (need_wire_pointer($e)) {
		pidl "if ($var_prefix$e->{NAME}) {";
		indent;
	}
	    
	if (util::array_size($e)) {
		ParseArrayPrint($e, $var_prefix)
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPrintSwitch($e, $var_prefix, $switch);
	} else {
		pidl "ndr_print_$e->{TYPE}(ndr, \"$e->{NAME}\", $cprefix$var_prefix$e->{NAME});";
	}

	if (need_wire_pointer($e)) {
		deindent;
		pidl "}";
	}	
}


#####################################################################
# parse buffers in a structure element - pull side
sub ParseElementPullBuffer($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $cprefix = c_pull_prefix($e);
	my $sub_size = util::has_property($e, "subcontext");

	if (is_pure_scalar($e)) {
		return;
	}

	start_flags($e);

	if (need_wire_pointer($e)) {
		pidl "if ($var_prefix$e->{NAME}) {";
		indent;
		if (util::has_property($e, "relative")) {
			pidl "struct ndr_pull_save _relative_save;";
			pidl "ndr_pull_save(ndr, &_relative_save);";
			pidl "NDR_CHECK(ndr_pull_relative_ptr2(ndr, $var_prefix$e->{NAME}));";
		}
	}
	    
	if (util::is_inline_array($e)) {
		ParseArrayPull($e, "r->", "NDR_BUFFERS");
	} elsif (util::array_size($e)) {
		ParseArrayPull($e, "r->", "NDR_SCALARS|NDR_BUFFERS");
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		if ($e->{POINTERS}) {
			ParseElementPullSwitch($e, $var_prefix, "NDR_SCALARS|NDR_BUFFERS", $switch);
		} else {
			ParseElementPullSwitch($e, $var_prefix, "NDR_BUFFERS", $switch);
		}
	} elsif (defined $sub_size) {
		if ($e->{POINTERS}) {
			pidl "NDR_CHECK(ndr_pull_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_flags_fn_t) ndr_pull_$e->{TYPE}));";
		}
	} elsif ($e->{POINTERS}) {
		pidl "NDR_CHECK(ndr_pull_$e->{TYPE}(ndr, NDR_SCALARS|NDR_BUFFERS, $cprefix$var_prefix$e->{NAME}));";
	} else {
		pidl "NDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));";
	}

	if (need_wire_pointer($e)) {
		if (util::has_property($e, "relative")) {
			pidl "ndr_pull_restore(ndr, &_relative_save);";
		}
		deindent;
		pidl "}";
	}	

	end_flags($e);
}

#####################################################################
# parse a struct
sub ParseStructPush($)
{
	my($struct) = shift;
	
	if (! defined $struct->{ELEMENTS}) {
		return;
	}

	start_flags($struct);

	# see if the structure contains a conformant array. If it
	# does, then it must be the last element of the structure, and
	# we need to push the conformant length early, as it fits on
	# the wire before the structure (and even before the structure
	# alignment)
	my $e = $struct->{ELEMENTS}[-1];
	if (defined $e->{ARRAY_LEN} && $e->{ARRAY_LEN} eq "*") {
		my $size = ParseExpr($e, util::array_size($e), "r->");
		$e->{CONFORMANT_SIZE} = $size;
		check_null_pointer($size);
		pidl "NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, $size));";
	}

	if (defined $e->{TYPE} && $e->{TYPE} eq "string" 
	    &&  util::property_matches($e, "flag", ".*LIBNDR_FLAG_STR_CONFORMANT.*")) {
		pidl "NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ndr_string_array_size(ndr, r->$e->{NAME})));";
	}

	pidl "if (!(ndr_flags & NDR_SCALARS)) goto buffers;";

	pidl "NDR_CHECK(ndr_push_struct_start(ndr));";

	my $align = find_largest_alignment($struct);
	pidl "NDR_CHECK(ndr_push_align(ndr, $align));";

	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPushScalar($e, "r->", "NDR_SCALARS");
	}	

	pidl "buffers:";
	pidl "if (!(ndr_flags & NDR_BUFFERS)) goto done;";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPushBuffer($e, "r->", "NDR_BUFFERS");
	}

	pidl "ndr_push_struct_end(ndr);";

	pidl "done:";

	end_flags($struct);
}


#####################################################################
# generate a push function for an enum
sub ParseEnumPush($)
{
	my($enum) = shift;
	my($type_fn) = util::enum_type_fn($enum);

	start_flags($enum);

	pidl "NDR_CHECK(ndr_push_$type_fn(ndr, NDR_SCALARS, r));";

	end_flags($enum);
}

#####################################################################
# generate a pull function for an enum
sub ParseEnumPull($)
{
	my($enum) = shift;
	my($type_fn) = util::enum_type_fn($enum);
	my($type_v_decl) = util::map_type(util::enum_type_fn($enum));

	pidl "$type_v_decl v;";
	start_flags($enum);
	pidl "NDR_CHECK(ndr_pull_$type_fn(ndr, NDR_SCALARS, &v));";
	pidl "*r = v;";

	end_flags($enum);
}

#####################################################################
# generate a print function for an enum
sub ParseEnumPrint($)
{
	my($enum) = shift;

	pidl "const char *val = NULL;";
	pidl "";

	start_flags($enum);

	pidl "switch (r) {";
	indent;
	my $els = \@{$enum->{ELEMENTS}};
	foreach my $i (0 .. $#{$els}) {
		my $e = ${$els}[$i];
		chomp $e;
		if ($e =~ /^(.*)=/) {
			$e = $1;
		}
		pidl "case $e: val = \"$e\"; break;";
	}

	deindent;
	pidl "}";
	
	pidl "ndr_print_enum(ndr, name, \"$enum->{TYPE}\", val, r);";

	end_flags($enum);
}

$typefamily{ENUM} = {
	PUSH_FN_BODY => \&ParseEnumPush,
	PULL_FN_BODY => \&ParseEnumPull,
	PRINT_FN_BODY => \&ParseEnumPrint,
	ALIGN => sub { return align_type(util::enum_type_fn(shift)); }
};

#####################################################################
# generate a push function for a bitmap
sub ParseBitmapPush($)
{
	my($bitmap) = shift;
	my($type_fn) = util::bitmap_type_fn($bitmap);

	start_flags($bitmap);

	pidl "NDR_CHECK(ndr_push_$type_fn(ndr, NDR_SCALARS, r));";

	end_flags($bitmap);
}

#####################################################################
# generate a pull function for an bitmap
sub ParseBitmapPull($)
{
	my($bitmap) = shift;
	my($type_fn) = util::bitmap_type_fn($bitmap);
	my($type_decl) = util::bitmap_type_decl($bitmap);

	pidl "$type_decl v;";
	start_flags($bitmap);
	pidl "NDR_CHECK(ndr_pull_$type_fn(ndr, NDR_SCALARS, &v));";
	pidl "*r = v;";

	end_flags($bitmap);
}

#####################################################################
# generate a print function for an bitmap
sub ParseBitmapPrintElement($$)
{
	my($e) = shift;
	my($bitmap) = shift;
	my($type_decl) = util::bitmap_type_decl($bitmap);
	my($type_fn) = util::bitmap_type_fn($bitmap);
	my($name) = $bitmap->{PARENT}->{NAME};
	my($flag);

	if ($e =~ /^(\w+) .*$/) {
		$flag = "$1";
	} else {
		die "Bitmap: \"$name\" invalid Flag: \"$e\"";
	}

	pidl "ndr_print_bitmap_flag(ndr, sizeof($type_decl), \"$flag\", $flag, r);";
}

#####################################################################
# generate a print function for an bitmap
sub ParseBitmapPrint($)
{
	my($bitmap) = shift;
	my($type_decl) = util::bitmap_type_decl($bitmap);
	my($type_fn) = util::bitmap_type_fn($bitmap);

	start_flags($bitmap);

	pidl "ndr_print_$type_fn(ndr, name, r);";

	pidl "ndr->depth++;";
	foreach my $e (@{$bitmap->{ELEMENTS}}) {
		ParseBitmapPrintElement($e, $bitmap);
	}
	pidl "ndr->depth--;";

	end_flags($bitmap);
}

$typefamily{BITMAP} = {
	PUSH_FN_BODY => \&ParseBitmapPush,
	PULL_FN_BODY => \&ParseBitmapPull,
	PRINT_FN_BODY => \&ParseBitmapPrint,
	ALIGN => sub { return align_type(util::bitmap_type_fn(shift)); }
};

#####################################################################
# generate a struct print function
sub ParseStructPrint($)
{
	my($struct) = shift;

	if (! defined $struct->{ELEMENTS}) {
		return;
	}

	start_flags($struct);

	pidl "ndr->depth++;";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPrintScalar($e, "r->");
	}
	pidl "ndr->depth--;";

	end_flags($struct);
}

#####################################################################
# parse a struct - pull side
sub ParseStructPull($)
{
	my($struct) = shift;
	my $conform_e;

	if (! defined $struct->{ELEMENTS}) {
		return;
	}

	# see if the structure contains a conformant array. If it
	# does, then it must be the last element of the structure, and
	# we need to pull the conformant length early, as it fits on
	# the wire before the structure (and even before the structure
	# alignment)
	my $e = $struct->{ELEMENTS}[-1];
	if (defined $e->{ARRAY_LEN} && $e->{ARRAY_LEN} eq "*") {
		$conform_e = $e;
	}

	if (defined $e->{TYPE} && $e->{TYPE} eq "string"
	    &&  util::property_matches($e, "flag", ".*LIBNDR_FLAG_STR_CONFORMANT.*")) {
		$conform_e = $e;
	}

	if (defined $conform_e) {
		$conform_e = $e;
		pidl "uint32_t _conformant_size;";
		$conform_e->{CONFORMANT_SIZE} = "_conformant_size";
	}

	# declare any internal pointers we need
	foreach my $e (@{$struct->{ELEMENTS}}) {
		if (need_wire_pointer($e)) {
			pidl "uint32_t _ptr_$e->{NAME};";
		}
	}

	start_flags($struct);

	pidl "if (!(ndr_flags & NDR_SCALARS)) goto buffers;";

	pidl "NDR_CHECK(ndr_pull_struct_start(ndr));";

	if (defined $conform_e) {
		pidl "NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &$conform_e->{CONFORMANT_SIZE}));";
	}

	my $align = find_largest_alignment($struct);
	pidl "NDR_CHECK(ndr_pull_align(ndr, $align));";

	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPullScalar($e, "r->", "NDR_SCALARS");
	}	

	pidl "buffers:\n";
	pidl "if (!(ndr_flags & NDR_BUFFERS)) goto done;";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPullBuffer($e, "r->", "NDR_BUFFERS");
	}

	foreach my $e (@{$struct->{ELEMENTS}}) {
		CheckArraySizes($e, "r->");
	}

	pidl "ndr_pull_struct_end(ndr);";

	pidl "done:";

	end_flags($struct);
}

#####################################################################
# calculate size of ndr struct
sub ParseStructNdrSize($)
{
	my $t = shift;
	my $static = fn_prefix($t);
	my $sizevar;

	pidl "size_t ndr_size_$t->{NAME}(const struct $t->{NAME} *r, int flags)";
	pidl "{";
	indent;
	if (my $flags = util::has_property($t, "flag")) {
		pidl "flags |= $flags;";
	}
	pidl "return ndr_size_struct(r, flags, (ndr_push_flags_fn_t)ndr_push_$t->{NAME});";
	deindent;
	pidl "}";
	pidl "";
}

$typefamily{STRUCT} = {
	PUSH_FN_BODY => \&ParseStructPush,
	PULL_FN_BODY => \&ParseStructPull,
	PRINT_FN_BODY => \&ParseStructPrint,
	SIZE_FN => \&ParseStructNdrSize,
	ALIGN => \&find_largest_alignment
};

#####################################################################
# calculate size of ndr struct
sub ParseUnionNdrSize($)
{
	my $t = shift;
	my $static = fn_prefix($t);
	my $sizevar;

	pidl "size_t ndr_size_$t->{NAME}(const union $t->{NAME} *r, int level, int flags)";
	pidl "{";
	indent;
	if (my $flags = util::has_property($t, "flag")) {
		pidl "flags |= $flags;";
	}
	pidl "return ndr_size_union(r, flags, level, (ndr_push_union_fn_t)ndr_push_$t->{NAME});";
	deindent;
	pidl "}";
	pidl "";;
}

#####################################################################
# parse a union - push side
sub ParseUnionPush($)
{
	my $e = shift;
	my $have_default = 0;

	start_flags($e);

	pidl "if (!(ndr_flags & NDR_SCALARS)) goto buffers;";

	pidl "NDR_CHECK(ndr_push_struct_start(ndr));";

#	my $align = union_alignment($e);
#	pidl "NDR_CHECK(ndr_push_align(ndr, $align));";

	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			pidl "default:";
			$have_default = 1;
		} else {
			pidl "case $el->{PROPERTIES}->{case}:";

		}
		if ($el->{TYPE} ne "EMPTY") {
			indent;
			ParseElementPushScalar($el, "r->", "NDR_SCALARS");
			deindent;
		}
		pidl "break;";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);";
	}
	deindent;
	pidl "}";
	pidl "buffers:";
	pidl "if (!(ndr_flags & NDR_BUFFERS)) goto done;";
	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			pidl "default:";
		} else {
			pidl "case $el->{PROPERTIES}->{case}:";
		}
		if ($el->{TYPE} ne "EMPTY") {
			indent;
			ParseElementPushBuffer($el, "r->", "NDR_BUFFERS");
			deindent;
		}
		pidl "break;";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);";
	}
	deindent;
	pidl "}";
	pidl "ndr_push_struct_end(ndr);";
	pidl "done:";
	end_flags($e);
}

#####################################################################
# print a union
sub ParseUnionPrint($)
{
	my $e = shift;
	my $have_default = 0;

	start_flags($e);

	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			$have_default = 1;
			pidl "default:";
		} else {
			pidl "case $el->{PROPERTIES}->{case}:";
		}
		if ($el->{TYPE} ne "EMPTY") {
			indent;
			ParseElementPrintScalar($el, "r->");
			deindent;
		}
		pidl "break;";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\tndr_print_bad_level(ndr, name, level);";
	}
	deindent;
	pidl "}";

	end_flags($e);
}

#####################################################################
# parse a union - pull side
sub ParseUnionPull($)
{
	my $e = shift;
	my $have_default = 0;

	start_flags($e);

	pidl "if (!(ndr_flags & NDR_SCALARS)) goto buffers;";

	pidl "NDR_CHECK(ndr_pull_struct_start(ndr));";

#	my $align = union_alignment($e);
#	pidl "\tNDR_CHECK(ndr_pull_align(ndr, $align));\n";

	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			pidl "default: {";
			$have_default = 1;
		} else {
			pidl "case $el->{PROPERTIES}->{case}: {";
		}
		if ($el->{TYPE} ne "EMPTY") {
			indent;
			if ($el->{POINTERS}) {
				pidl "uint32_t _ptr_$el->{NAME};";
			}
			ParseElementPullScalar($el, "r->", "NDR_SCALARS");
			deindent;
		}
		pidl "break; }";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);";
	}
	deindent;
	pidl "}";
	pidl "buffers:";
	pidl "if (!(ndr_flags & NDR_BUFFERS)) goto done;";
	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			pidl "default:";
		} else {
			pidl "case $el->{PROPERTIES}->{case}:";
		}
		if ($el->{TYPE} ne "EMPTY") {
			indent;
			ParseElementPullBuffer($el, "r->", "NDR_BUFFERS");
			deindent;
		}
		pidl "break;";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);";
	}
	deindent;
	pidl "}";
	pidl "ndr_pull_struct_end(ndr);";
	pidl "done:";
	end_flags($e);
}

$typefamily{UNION} = {
	PUSH_FN_BODY => \&ParseUnionPush,
	PULL_FN_BODY => \&ParseUnionPull,
	PRINT_FN_BODY => \&ParseUnionPrint,
	SIZE_FN => \&ParseUnionNdrSize,
	ALIGN => \&find_largest_alignment
};

	
#####################################################################
# parse a typedef - push side
sub ParseTypedefPush($)
{
	my($e) = shift;
	my $static = fn_prefix($e);

	if (! needed::is_needed("push_$e->{NAME}")) {
#		print "push_$e->{NAME} not needed\n";
		return;
	}

	my $args;
	if ($e->{DATA}->{TYPE} eq "STRUCT") {
		$args = "struct ndr_push *ndr, int ndr_flags, struct $e->{NAME} *r";
	}

	if ($e->{DATA}->{TYPE} eq "UNION") {
		$args = "struct ndr_push *ndr, int ndr_flags, int level, union $e->{NAME} *r";
	}

	if ($e->{DATA}->{TYPE} eq "ENUM") {
		$args = "struct ndr_push *ndr, int ndr_flags, enum $e->{NAME} r";
	}

	if ($e->{DATA}->{TYPE} eq "BITMAP") {
		my $type_decl = util::bitmap_type_decl($e->{DATA});
		$args = "struct ndr_push *ndr, int ndr_flags, $type_decl r";
	}
	
	pidl $static . "NTSTATUS ndr_push_$e->{NAME}($args)";

	pidl "{";
	indent;
	$typefamily{$e->{DATA}->{TYPE}}->{PUSH_FN_BODY}($e->{DATA});
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";
	pidl "";;
}

#####################################################################
# parse a typedef - pull side
sub ParseTypedefPull($)
{
	my($e) = shift;
	my $static = fn_prefix($e);

	if (! needed::is_needed("pull_$e->{NAME}")) {
#		print "pull_$e->{NAME} not needed\n";
		return;
	}

	my $args = "";

	if ($e->{DATA}->{TYPE} eq "STRUCT") {
		$args = "struct ndr_pull *ndr, int ndr_flags, struct $e->{NAME} *r";
	}

	if ($e->{DATA}->{TYPE} eq "UNION") {
		$args = "struct ndr_pull *ndr, int ndr_flags, int level, union $e->{NAME} *r";
	}

	if ($e->{DATA}->{TYPE} eq "ENUM") {
		$args = "struct ndr_pull *ndr, int ndr_flags, enum $e->{NAME} *r";
	}

	if ($e->{DATA}->{TYPE} eq "BITMAP") {
		my $type_decl = util::bitmap_type_decl($e->{DATA});
		$args = "struct ndr_pull *ndr, int ndr_flags, $type_decl *r";
	}
	
	pidl $static . "NTSTATUS ndr_pull_$e->{NAME}($args)";

	pidl "{";
	indent;
	$typefamily{$e->{DATA}->{TYPE}}->{PULL_FN_BODY}($e->{DATA});
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# parse a typedef - print side
sub ParseTypedefPrint($)
{
	my($e) = shift;

	if ($e->{DATA}->{TYPE} eq "STRUCT") {
		pidl "void ndr_print_$e->{NAME}(struct ndr_print *ndr, const char *name, struct $e->{NAME} *r)";
		pidl "{";
		indent;
		pidl "ndr_print_struct(ndr, name, \"$e->{NAME}\");";
	}

	if ($e->{DATA}->{TYPE} eq "UNION") {
		pidl "void ndr_print_$e->{NAME}(struct ndr_print *ndr, const char *name, int level, union $e->{NAME} *r)";
		pidl "{";
		indent;
		pidl "ndr_print_union(ndr, name, level, \"$e->{NAME}\");";
	}

	if ($e->{DATA}->{TYPE} eq "ENUM") {
		pidl "void ndr_print_$e->{NAME}(struct ndr_print *ndr, const char *name, enum $e->{NAME} r)";
		pidl "{";
		indent;
	}

	if ($e->{DATA}->{TYPE} eq "BITMAP") {
		my $type_decl = util::bitmap_type_decl($e->{DATA});
		pidl "void ndr_print_$e->{NAME}(struct ndr_print *ndr, const char *name, $type_decl r)";
		pidl "{";
		indent;
	}

	$typefamily{$e->{DATA}->{TYPE}}->{PRINT_FN_BODY}($e->{DATA});
	deindent;
	pidl "}";
}

#####################################################################
## calculate the size of a structure
sub ParseTypedefNdrSize($)
{
	my($t) = shift;
	if (! needed::is_needed("ndr_size_$t->{NAME}")) {
		return;
	}

	$typefamily{$t->{DATA}->{TYPE}}->{SIZE_FN}($t);
}

#####################################################################
# parse a function - print side
sub ParseFunctionPrint($)
{
	my($fn) = shift;

	pidl "void ndr_print_$fn->{NAME}(struct ndr_print *ndr, const char *name, int flags, struct $fn->{NAME} *r)";
	pidl "{";
	indent;
	pidl "ndr_print_struct(ndr, name, \"$fn->{NAME}\");";
	pidl "ndr->depth++;";

	pidl "if (flags & NDR_SET_VALUES) {";
	pidl "\tndr->flags |= LIBNDR_PRINT_SET_VALUES;";
	pidl "}";

	pidl "if (flags & NDR_IN) {";
	indent;
	pidl "ndr_print_struct(ndr, \"in\", \"$fn->{NAME}\");";
	pidl "ndr->depth++;";

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "in")) {
			ParseElementPrintScalar($e, "r->in.");
		}
	}
	pidl "ndr->depth--;";
	deindent;
	pidl "}";
	
	pidl "if (flags & NDR_OUT) {";
	indent;
	pidl "ndr_print_struct(ndr, \"out\", \"$fn->{NAME}\");";
	pidl "ndr->depth++;";
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "out")) {
			ParseElementPrintScalar($e, "r->out.");
		}
	}
	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		my $cprefix = "&";
		$cprefix = "" if (is_scalar_type($fn->{RETURN_TYPE})) ; # FIXME: Should really use util::c_push_prefix here
		pidl "ndr_print_$fn->{RETURN_TYPE}(ndr, \"result\", $cprefix"."r->out.result);";
	}
	pidl "ndr->depth--;";
	deindent;
	pidl "}";
	
	pidl "ndr->depth--;";
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# parse a function element
sub ParseFunctionElementPush($$)
{ 
	my $e = shift;
	my $inout = shift;

	if (util::array_size($e)) {
		if (need_wire_pointer($e)) {
			pidl "NDR_CHECK(ndr_push_unique_ptr(ndr, r->$inout.$e->{NAME}));";
			pidl "if (r->$inout.$e->{NAME}) {";
			indent;
			ParseArrayPush($e, "r->$inout.", "NDR_SCALARS|NDR_BUFFERS");
			deindent;
			pidl "}";
		} else {
			ParseArrayPush($e, "r->$inout.", "NDR_SCALARS|NDR_BUFFERS");
		}
	} else {
		ParseElementPushScalar($e, "r->$inout.", "NDR_SCALARS|NDR_BUFFERS");

		if ($e->{POINTERS}) {
			ParseElementPushBuffer($e, "r->$inout.", "NDR_SCALARS|NDR_BUFFERS");
		}
	}
}	

#####################################################################
# parse a function
sub ParseFunctionPush($)
{ 
	my($fn) = shift;
	my $static = fn_prefix($fn);

	pidl $static . "NTSTATUS ndr_push_$fn->{NAME}(struct ndr_push *ndr, int flags, struct $fn->{NAME} *r)";
	pidl "{";
	indent;

	pidl "if (!(flags & NDR_IN)) goto ndr_out;";
	pidl "";

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "in")) {
			ParseFunctionElementPush($e, "in");
		}		
	}

	pidl "ndr_out:";
	pidl "if (!(flags & NDR_OUT)) goto done;";
	pidl "";

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "out")) {
			ParseFunctionElementPush($e, "out");
		}		
	}

	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		pidl "NDR_CHECK(ndr_push_$fn->{RETURN_TYPE}(ndr, NDR_SCALARS, r->out.result));";
	}
    
	pidl "done:";
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# parse a function element
sub ParseFunctionElementPull($$)
{ 
	my $e = shift;
	my $inout = shift;

	if (util::array_size($e)) {
		if (need_wire_pointer($e)) {
			pidl "NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_$e->{NAME}));";
			pidl "r->$inout.$e->{NAME} = NULL;";
			pidl "if (_ptr_$e->{NAME}) {";
			indent;
		} elsif ($inout eq "out" && util::has_property($e, "ref")) {
			pidl "if (r->$inout.$e->{NAME}) {";
			indent;
		} else {
			pidl "{";
			indent;
		}
		ParseArrayPull($e, "r->$inout.", "NDR_SCALARS|NDR_BUFFERS");
		deindent;
		pidl "}";
	} else {
		if ($inout eq "out" && util::has_property($e, "ref")) {
			pidl "if (ndr->flags & LIBNDR_FLAG_REF_ALLOC) {";
			pidl "\tNDR_ALLOC(ndr, r->out.$e->{NAME});";
			pidl "}";
		}
		if ($inout eq "in" && util::has_property($e, "ref")) {
			pidl "NDR_ALLOC(ndr, r->in.$e->{NAME});";
		}

		ParseElementPullScalar($e, "r->$inout.", "NDR_SCALARS|NDR_BUFFERS");
		if ($e->{POINTERS}) {
			ParseElementPullBuffer($e, "r->$inout.", "NDR_SCALARS|NDR_BUFFERS");
		}
	}
}

############################################################
# allocate ref variables
sub AllocateRefVars($)
{
	my $e = shift;
	my $asize = util::array_size($e);

	# note that if the variable is also an "in"
	# variable then we copy the initial value from
	# the in side

	if (!defined $asize) {
		# its a simple variable
		pidl "NDR_ALLOC(ndr, r->out.$e->{NAME});";
		if (util::has_property($e, "in")) {
			pidl "*r->out.$e->{NAME} = *r->in.$e->{NAME};";
		} else {
			pidl "ZERO_STRUCTP(r->out.$e->{NAME});";
		}
		return;
	}

	# its an array
	my $size = ParseExpr($e, $asize, "r->out.");
	check_null_pointer($size);
	pidl "NDR_ALLOC_N(ndr, r->out.$e->{NAME}, $size);";
	if (util::has_property($e, "in")) {
		pidl "memcpy(r->out.$e->{NAME},r->in.$e->{NAME},$size * sizeof(*r->in.$e->{NAME}));";
	} else {
		pidl "memset(r->out.$e->{NAME}, 0, $size * sizeof(*r->out.$e->{NAME}));";
	}
}

#####################################################################
# parse a function
sub ParseFunctionPull($)
{ 
	my($fn) = shift;
	my $static = fn_prefix($fn);

	# pull function args
	pidl $static . "NTSTATUS ndr_pull_$fn->{NAME}(struct ndr_pull *ndr, int flags, struct $fn->{NAME} *r)";
	pidl "{";
	indent;

	# declare any internal pointers we need
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (need_wire_pointer($e)) {
			pidl "uint32_t _ptr_$e->{NAME};";
		}
	}

	pidl "if (!(flags & NDR_IN)) goto ndr_out;";
	pidl "";

	# auto-init the out section of a structure. I originally argued that
	# this was a bad idea as it hides bugs, but coping correctly
	# with initialisation and not wiping ref vars is turning
	# out to be too tricky (tridge)
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "out")) {
			pidl "ZERO_STRUCT(r->out);";
			pidl "";
			last;
		}
	}

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "in")) {
			ParseFunctionElementPull($e, "in");
		}
		# we need to allocate any reference output variables, so that
		# a dcerpc backend can be sure they are non-null
		if (util::has_property($e, "out") && util::has_property($e, "ref")) {
			AllocateRefVars($e);
		}
	}

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "in")) {
			CheckArraySizes($e, "r->in.");
		}
	}

	pidl "ndr_out:";
	pidl "if (!(flags & NDR_OUT)) goto done;";
	pidl "";

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "out")) {
			ParseFunctionElementPull($e, "out");
		}
	}

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "out")) {
			CheckArraySizes($e, "r->out.");
		}
	}

	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		pidl "NDR_CHECK(ndr_pull_$fn->{RETURN_TYPE}(ndr, NDR_SCALARS, &r->out.result));";
	}

	pidl "done:";
	pidl "";
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# produce a function call table
sub FunctionTable($)
{
	my($interface) = shift;
	my($data) = $interface->{INHERITED_DATA};
	my $count = 0;
	my $uname = uc $interface->{NAME};

	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") { $count++; }
	}

	return if ($count == 0);

	pidl "static const struct dcerpc_interface_call $interface->{NAME}\_calls[] = {";
	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") {
			pidl "\t{";
			pidl "\t\t\"$d->{NAME}\",";
			pidl "\t\tsizeof(struct $d->{NAME}),";
			pidl "\t\t(ndr_push_flags_fn_t) ndr_push_$d->{NAME},";
			pidl "\t\t(ndr_pull_flags_fn_t) ndr_pull_$d->{NAME},";
			pidl "\t\t(ndr_print_function_t) ndr_print_$d->{NAME}";
			pidl "\t},";
		}
	}
	pidl "\t{ NULL, 0, NULL, NULL, NULL }";
	pidl "};";
	pidl "";

	# If no endpoint is set, default to the interface name as a named pipe
	if (! defined $interface->{PROPERTIES}->{endpoint}) {
		$interface->{PROPERTIES}->{endpoint} = "\"ncacn_np:[\\\\pipe\\\\" . $interface->{NAME} . "]\"";
	}

	my @e = split / /, $interface->{PROPERTIES}->{endpoint};
	my $endpoint_count = $#e + 1;

	pidl "static const char * const $interface->{NAME}\_endpoint_strings[] = {";
	foreach my $ep (@e) {
		pidl "\t$ep, ";
	}
	pidl "};";
	pidl "";

	pidl "static const struct dcerpc_endpoint_list $interface->{NAME}\_endpoints = {";
	pidl "\t$endpoint_count, $interface->{NAME}\_endpoint_strings";
	pidl "};";
	pidl "";

	pidl "\nconst struct dcerpc_interface_table dcerpc_table_$interface->{NAME} = {";
	pidl "\t\"$interface->{NAME}\",";
	pidl "\tDCERPC_$uname\_UUID,";
	pidl "\tDCERPC_$uname\_VERSION,";
	pidl "\tDCERPC_$uname\_HELPSTRING,";
	pidl "\t$count,";
	pidl "\t$interface->{NAME}\_calls,";
	pidl "\t&$interface->{NAME}\_endpoints";
	pidl "};";
	pidl "";

	pidl "static NTSTATUS dcerpc_ndr_$interface->{NAME}_init(void)";
	pidl "{";
	pidl "\treturn librpc_register_interface(&dcerpc_table_$interface->{NAME});";
	pidl "}";
	pidl "";
}

#####################################################################
# parse the interface definitions
sub ParseInterface($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};

	# Push functions
	foreach my $d (@{$data}) {
		($d->{TYPE} eq "TYPEDEF") &&
		    ParseTypedefPush($d);
		($d->{TYPE} eq "FUNCTION") && 
		    ParseFunctionPush($d);
	}

	# Pull functions
	foreach my $d (@{$data}) {
		($d->{TYPE} eq "TYPEDEF") &&
		    ParseTypedefPull($d);
		($d->{TYPE} eq "FUNCTION") && 
		    ParseFunctionPull($d);
	}
	
	# Print functions
	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "TYPEDEF" &&
		    !util::has_property($d, "noprint")) {
			ParseTypedefPrint($d);
		}
		if ($d->{TYPE} eq "FUNCTION" &&
		    !util::has_property($d, "noprint")) {
			ParseFunctionPrint($d);
		}
	}

	# Size functions
	foreach my $d (@{$data}) {
		($d->{TYPE} eq "TYPEDEF") && 
			ParseTypedefNdrSize($d);
	}

	FunctionTable($interface);
}

sub RegistrationFunction($$)
{
	my $idl = shift;
	my $filename = shift;

	$filename =~ /.*\/ndr_(.*).c/;
	my $basename = $1;
	pidl "NTSTATUS dcerpc_$basename\_init(void)";
	pidl "{";
	indent;
	pidl "NTSTATUS status = NT_STATUS_OK;";
	foreach my $interface (@{$idl}) {
		next if $interface->{TYPE} ne "INTERFACE";

		my $data = $interface->{INHERITED_DATA};
		my $count = 0;
		foreach my $d (@{$data}) {
			if ($d->{TYPE} eq "FUNCTION") { $count++; }
		}

		next if ($count == 0);

		pidl "status = dcerpc_ndr_$interface->{NAME}_init();";
		pidl "if (NT_STATUS_IS_ERR(status)) {";
		pidl "\treturn status;";
		pidl "}";
		pidl "";
	}
	pidl "return status;";
	deindent;
	pidl "}";
	pidl "";
}

sub CheckPointerTypes($$)
{
	my $s = shift;
	my $default = shift;

	foreach my $e (@{$s->{ELEMENTS}}) {
		if ($e->{POINTERS}) {
			if (not defined(pointer_type($e))) {
				$e->{PROPERTIES}->{$default} = 1;
			}

			if (pointer_type($e) eq "ptr") {
				print "Warning: ptr is not supported by pidl yet\n";
			}
		}
	}
}

sub LoadInterface($)
{
	my $x = shift;

	if (not util::has_property($x, "pointer_default")) {
		# MIDL defaults to "ptr" in DCE compatible mode (/osf)
		# and "unique" in Microsoft Extensions mode (default)
		$x->{PROPERTIES}->{pointer_default} = "unique";
	}

	foreach my $d (@{$x->{DATA}}) {
		if (($d->{TYPE} eq "DECLARE") or ($d->{TYPE} eq "TYPEDEF")) {
		    $typedefs{$d->{NAME}} = $d;
			if ($d->{DATA}->{TYPE} eq "STRUCT" or $d->{DATA}->{TYPE} eq "UNION") {
				CheckPointerTypes($d->{DATA}, $x->{PROPERTIES}->{pointer_default});
			}

			if (defined($d->{PROPERTIES}) && !defined($d->{DATA}->{PROPERTIES})) {
				$d->{DATA}->{PROPERTIES} = $d->{PROPERTIES};
			}
		}
		if ($d->{TYPE} eq "FUNCTION") {
			CheckPointerTypes($d, 
				$x->{PROPERTIES}->{pointer_default}  # MIDL defaults to "ref"
			);
		}
	}
}

# Add ORPC specific bits to an interface.
sub InterfaceORPC($)
{
	my $x = shift;	
	# Add [in] ORPCTHIS *this, [out] ORPCTHAT *that
	# for 'object' interfaces
	if (util::has_property($x, "object")) {
		foreach my $e (@{$x->{DATA}}) {
			if($e->{TYPE} eq "FUNCTION") {
				$e->{PROPERTIES}->{object} = 1;
				unshift(@{$e->{ELEMENTS}}, 
                       { 'NAME' => 'ORPCthis',
                         'POINTERS' => 0,
                         'PROPERTIES' => { 'in' => '1' },
                         'TYPE' => 'ORPCTHIS'
                       });
				unshift(@{$e->{ELEMENTS}},
                       { 'NAME' => 'ORPCthat',
                         'POINTERS' => 0,
                         'PROPERTIES' => { 'out' => '1' },
					  'TYPE' => 'ORPCTHAT'
                       });
			}
		}
	}
}

sub Load($)
{
	my $idl = shift;

	foreach my $x (@{$idl}) {
		LoadInterface($x);
	}
}

#####################################################################
# parse a parsed IDL structure back into an IDL file
sub Parse($$)
{
	my($idl) = shift;
	my($filename) = shift;
	my $h_filename = $filename;
	$res = "";

	Load($idl);

	if ($h_filename =~ /(.*)\.c/) {
		$h_filename = "$1.h";
	}

	pidl "/* parser auto-generated by pidl */";
	pidl "";
	pidl "#include \"includes.h\"";
	pidl "#include \"$h_filename\"";
	pidl "";

	foreach my $x (@{$idl}) {
		if ($x->{TYPE} eq "INTERFACE") { 
			needed::BuildNeeded($x);
			ParseInterface($x);
		}
	}

	RegistrationFunction($idl, $filename);

	return $res;
}

RegisterPrimitives();

1;
