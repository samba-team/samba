###################################################
# Samba4 NDR parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# Copyright jelmer@samba.org 2004
# released under the GNU GPL

package NdrParser;

use strict;
use needed;

# list of known types
my %typedefs;

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

sub is_scalar_type($)
{
    my $type = shift;

	return 1 if (defined($typedefs{$type}) and $typedefs{$type}->{DATA}->{TYPE} eq "SCALAR");
    return 1 if (util::is_enum($type));
	return 1 if (util::is_bitmap($type));

    return 0;
}

# determine if an element needs a reference pointer on the wire
# in its NDR representation
sub need_wire_pointer($)
{
	my $e = shift;
	if ($e->{POINTERS} && 
	    !util::has_property($e, "ref")) {
		return $e->{POINTERS};
	}
	return undef;
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
sub pidl($)
{
	$res .= shift;
}

#####################################################################
# parse a properties list
sub ParseProperties($)
{
    my($props) = shift;
    foreach my $d (@{$props}) {
	if (ref($d) ne "HASH") {
	    pidl "[$d] ";
	} else {
	    foreach my $k (keys %{$d}) {
		pidl "[$k($d->{$k})] ";
	    }
	}
    }
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
sub find_size_var($$$)
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
# check that a variable we get from find_size_var isn't a null pointer
sub check_null_pointer($)
{
	my $size = shift;
	if ($size =~ /^\*/) {
		my $size2 = substr($size, 1);
		pidl "\tif ($size2 == NULL) return NT_STATUS_INVALID_PARAMETER_MIX;\n";
	}
}

#####################################################################
# check that a variable we get from find_size_var isn't a null pointer
# void return varient
sub check_null_pointer_void($)
{
	my $size = shift;
	if ($size =~ /^\*/) {
		my $size2 = substr($size, 1);
		pidl "\tif ($size2 == NULL) return;\n";
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
		pidl "\t{ uint32_t _flags_save_$e->{TYPE} = ndr->flags;\n";
		pidl "\tndr_set_flags(&ndr->flags, $flags);\n";
	}
}

###################################################################
# end any special flags for an element or structure
sub end_flags($)
{
	my $e = shift;
	my $flags = util::has_property($e, "flag");
	if (defined $flags) {
		pidl "\tndr->flags = _flags_save_$e->{TYPE};\n\t}\n";
	}
}


#####################################################################
# work out the correct alignment for a structure or union
sub struct_alignment
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

	unless (defined($typedefs{$e})) {
	    # it must be an external type - all we can do is guess 
		# print "Warning: assuming alignment of unknown type '$e' is 4\n";
	    return 4;
	}

	my $dt = $typedefs{$e}->{DATA};

	if ($dt->{TYPE} eq "STRUCT") {
		return struct_alignment($dt);
	} elsif($dt->{TYPE} eq "UNION") {
		return struct_alignment($dt);
	} elsif ($dt->{TYPE} eq "ENUM") {
	   	return align_type(util::enum_type_fn(util::get_enum($e)));
	} elsif ($dt->{TYPE} eq "BITMAP") {
		return align_type(util::bitmap_type_fn(util::get_bitmap($e)));
	} elsif ($dt->{TYPE} eq "SCALAR") {
		return $dt->{ALIGN};
	}

	die("Internal pidl error. Typedef has unknown data type $dt->{TYPE}!");
}

#####################################################################
# parse an array - push side
sub ParseArrayPush($$$)
{
	my $e = shift;
	my $var_prefix = shift;
	my $ndr_flags = shift;

	my $size = find_size_var($e, util::array_size($e), $var_prefix);

	if (defined $e->{CONFORMANT_SIZE}) {
		# the conformant size has already been pushed
	} elsif (!util::is_inline_array($e)) {
		# we need to emit the array size
		pidl "\t\tNDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, $size));\n";
	}

	if (my $length = util::has_property($e, "length_is")) {
		$length = find_size_var($e, $length, $var_prefix);
		pidl "\t\tNDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));\n";
		pidl "\t\tNDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, $length));\n";
		$size = $length;
	}

	if (is_scalar_type($e->{TYPE})) {
		pidl "\t\tNDR_CHECK(ndr_push_array_$e->{TYPE}(ndr, $ndr_flags, $var_prefix$e->{NAME}, $size));\n";
	} else {
		pidl "\t\tNDR_CHECK(ndr_push_array(ndr, $ndr_flags, $var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_push_flags_fn_t)ndr_push_$e->{TYPE}));\n";
	}
}

#####################################################################
# print an array
sub ParseArrayPrint($$)
{
	my $e = shift;
	my $var_prefix = shift;
	my $size = find_size_var($e, util::array_size($e), $var_prefix);
	my $length = util::has_property($e, "length_is");

	if (defined $length) {
		$size = find_size_var($e, $length, $var_prefix);
	}

	if (is_scalar_type($e->{TYPE})) {
		pidl "\t\tndr_print_array_$e->{TYPE}(ndr, \"$e->{NAME}\", $var_prefix$e->{NAME}, $size);\n";
	} else {
		pidl "\t\tndr_print_array(ndr, \"$e->{NAME}\", $var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_print_fn_t)ndr_print_$e->{TYPE});\n";
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
		my $size = find_size_var($e, util::array_size($e), $var_prefix);
		pidl "\tif ($var_prefix$e->{NAME}) {\n";
		check_null_pointer($size);
		pidl "\t\tNDR_CHECK(ndr_check_array_size(ndr, (void*)&$var_prefix$e->{NAME}, $size));\n";
		pidl "\t}\n";
	}

	if (my $length = util::has_property($e, "length_is")) {
		$length = find_size_var($e, $length, $var_prefix);
		pidl "\tif ($var_prefix$e->{NAME}) {\n";
		check_null_pointer($length);
		pidl "\t\tNDR_CHECK(ndr_check_array_length(ndr, (void*)&$var_prefix$e->{NAME}, $length));\n";
		pidl "\t}\n";
	}
}


#####################################################################
# parse an array - pull side
sub ParseArrayPull($$$)
{
	my $e = shift;
	my $var_prefix = shift;
	my $ndr_flags = shift;

	my $size = find_size_var($e, util::array_size($e), $var_prefix);
	my $alloc_size = $size;

	# if this is a conformant array then we use that size to allocate, and make sure
	# we allocate enough to pull the elements
	if (defined $e->{CONFORMANT_SIZE}) {
		$alloc_size = $e->{CONFORMANT_SIZE};
		check_null_pointer($size);
		pidl "\tif ($size > $alloc_size) {\n";
		pidl "\t\treturn ndr_pull_error(ndr, NDR_ERR_CONFORMANT_SIZE, \"Bad conformant size %u should be %u\", $alloc_size, $size);\n";
		pidl "\t}\n";
	} elsif (!util::is_inline_array($e)) {
		if ($var_prefix =~ /^r->out/ && $size =~ /^\*r->in/) {
			my $size2 = substr($size, 1);
			pidl "if (ndr->flags & LIBNDR_FLAG_REF_ALLOC) {	NDR_ALLOC(ndr, $size2); }\n";
		}

		# non fixed arrays encode the size just before the array
		pidl "\t\tNDR_CHECK(ndr_pull_array_size(ndr, &$var_prefix$e->{NAME}));\n";
		$alloc_size = "ndr_get_array_size(ndr, &$var_prefix$e->{NAME})";
	}

	if ((need_alloc($e) && !util::is_fixed_array($e)) ||
	    ($var_prefix eq "r->in." && util::has_property($e, "ref"))) {
		if (!util::is_inline_array($e) || $ndr_flags eq "NDR_SCALARS") {
			pidl "\t\tNDR_ALLOC_N(ndr, $var_prefix$e->{NAME}, $alloc_size);\n";
		}
	}

	if (($var_prefix eq "r->out." && util::has_property($e, "ref"))) {
		if (!util::is_inline_array($e) || $ndr_flags eq "NDR_SCALARS") {
			pidl "\tif (ndr->flags & LIBNDR_FLAG_REF_ALLOC) {";
			pidl "\t\tNDR_ALLOC_N(ndr, $var_prefix$e->{NAME}, $alloc_size);\n";
			pidl "\t}\n";
		}
	}

	if (my $length = util::has_property($e, "length_is")) {
		pidl "\t\tNDR_CHECK(ndr_pull_array_length(ndr, &$var_prefix$e->{NAME}));\n";
		$size = "ndr_get_array_length(ndr, &$var_prefix$e->{NAME})";
	}

	check_null_pointer($size);
	if (is_scalar_type($e->{TYPE})) {
		pidl "\t\tNDR_CHECK(ndr_pull_array_$e->{TYPE}(ndr, $ndr_flags, $var_prefix$e->{NAME}, $size));\n";
	} else {
		pidl "\t\tNDR_CHECK(ndr_pull_array(ndr, $ndr_flags, (void **)$var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_pull_flags_fn_t)ndr_pull_$e->{TYPE}));\n";
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
		pidl "\t$cprefix$var_prefix$e->{NAME} = $value;\n";
	}

	if (util::has_property($e, "relative")) {
		pidl "\tNDR_CHECK(ndr_push_relative1(ndr, $var_prefix$e->{NAME}));\n";
	} elsif (util::is_inline_array($e)) {
		ParseArrayPush($e, "r->", "NDR_SCALARS");
	} elsif (need_wire_pointer($e)) {
		pidl "\tNDR_CHECK(ndr_push_ptr(ndr, $var_prefix$e->{NAME}));\n";
	} elsif (need_alloc($e)) {
		# no scalar component
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPushSwitch($e, $var_prefix, $ndr_flags, $switch);
	} elsif (defined $sub_size) {
		pidl "\tNDR_CHECK(ndr_push_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_push_flags_fn_t) ndr_push_$e->{TYPE}));\n";
	} else {
		pidl "\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));\n";
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
		pidl "\tif (ndr->flags & LIBNDR_PRINT_SET_VALUES) {\n";
		pidl "\t\t$cprefix$var_prefix$e->{NAME} = $value;\n";
		pidl "\t}\n";
	}

	if (util::is_fixed_array($e)) {
		ParseElementPrintBuffer($e, $var_prefix);
	} elsif ($e->{POINTERS} || util::array_size($e)) {
		pidl "\tndr_print_ptr(ndr, \"$e->{NAME}\", $var_prefix$e->{NAME});\n";
		pidl "\tndr->depth++;\n";
		ParseElementPrintBuffer($e, $var_prefix);
		pidl "\tndr->depth--;\n";
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPrintSwitch($e, $var_prefix, $switch);
	} else {
		pidl "\tndr_print_$e->{TYPE}(ndr, \"$e->{NAME}\", $cprefix$var_prefix$e->{NAME});\n";
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
	my $switch_var = find_size_var($e, $switch, $var_prefix);

	my $cprefix = c_pull_prefix($e);

	my $utype = $typedefs{$e->{TYPE}};

	check_null_pointer($switch_var);

	if (!defined $utype ||
	    !util::has_property($utype, "nodiscriminant")) {
		my $e2 = find_sibling($e, $switch);
		my $type_decl = util::map_type($e2->{TYPE});
		pidl "\tif (($ndr_flags) & NDR_SCALARS) {\n";
		if (util::is_enum($e2->{TYPE})) {
			$type_decl = util::enum_type_decl($e2);
		} elsif (util::is_bitmap($e2->{TYPE})) {
			$type_decl = util::bitmap_type_decl($e2);
		}
		pidl "\t\t$type_decl _level;\n";
		pidl "\t\tNDR_CHECK(ndr_pull_$e2->{TYPE}(ndr, NDR_SCALARS, &_level));\n";
		if ($switch_var =~ /r->in/) {
			pidl "\t\tif (!(ndr->flags & LIBNDR_FLAG_REF_ALLOC) && _level != $switch_var) {\n";
		} else {
			pidl "\t\tif (_level != $switch_var) {\n";
		}
		pidl "\t\t\treturn ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value %u in $e->{NAME}\", _level);\n";
		pidl "\t\t}\n";
		if ($switch_var =~ /r->/) {
			pidl "else { $switch_var = _level; }\n";
		}
		pidl "\t}\n";
	}

	my $sub_size = util::has_property($e, "subcontext");
	if (defined $sub_size) {
		pidl "\tif (($ndr_flags) & NDR_SCALARS) {\n";
		pidl "\t\tNDR_CHECK(ndr_pull_subcontext_union_fn(ndr, $sub_size, $switch_var, $cprefix$var_prefix$e->{NAME}, (ndr_pull_union_fn_t) ndr_pull_$e->{TYPE}));\n";
		pidl "\t}\n";
	} else {
		pidl "\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $ndr_flags, $switch_var, $cprefix$var_prefix$e->{NAME}));\n";
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
	my $switch_var = find_size_var($e, $switch, $var_prefix);
	my $cprefix = c_push_prefix($e);

	check_null_pointer($switch_var);

	my $utype = $typedefs{$e->{TYPE}};
	if (!defined $utype ||
	    !util::has_property($utype, "nodiscriminant")) {
		my $e2 = find_sibling($e, $switch);
		pidl "\tif (($ndr_flags) & NDR_SCALARS) {\n";
		pidl "\t\tNDR_CHECK(ndr_push_$e2->{TYPE}(ndr, NDR_SCALARS, $switch_var));\n";
		pidl "\t}\n";
	}

	my $sub_size = util::has_property($e, "subcontext");
	if (defined $sub_size) {
		pidl "\tif(($ndr_flags) & NDR_SCALARS) {\n";
		pidl "\t\tNDR_CHECK(ndr_push_subcontext_union_fn(ndr, $sub_size, $switch_var, $cprefix$var_prefix$e->{NAME}, (ndr_push_union_fn_t) ndr_push_$e->{TYPE}));\n";
		pidl "\t}\n";
	} else {
		pidl "\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $ndr_flags, $switch_var, $cprefix$var_prefix$e->{NAME}));\n";
	}
}

#####################################################################
# print scalars in a structure element 
sub ParseElementPrintSwitch($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my $switch = shift;
	my $switch_var = find_size_var($e, $switch, $var_prefix);
	my $cprefix = c_push_prefix($e);

	check_null_pointer_void($switch_var);

	pidl "\tndr_print_$e->{TYPE}(ndr, \"$e->{NAME}\", $switch_var, $cprefix$var_prefix$e->{NAME});\n";
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
		pidl "\tNDR_CHECK(ndr_pull_ptr(ndr, &_ptr_$e->{NAME}));\n";
		pidl "\tif (_ptr_$e->{NAME}) {\n";
		pidl "\t\tNDR_ALLOC(ndr, $var_prefix$e->{NAME});\n";
		if (util::has_property($e, "relative")) {
			pidl "\t\tNDR_CHECK(ndr_pull_relative1(ndr, $var_prefix$e->{NAME}, _ptr_$e->{NAME}));\n";
		}
		pidl "\t} else {\n";
		pidl "\t\t$var_prefix$e->{NAME} = NULL;\n";
		pidl "\t}\n";
	} elsif (need_alloc($e)) {
		# no scalar component
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPullSwitch($e, $var_prefix, $ndr_flags, $switch);
	} elsif (defined $sub_size) {
		pidl "\tNDR_CHECK(ndr_pull_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_flags_fn_t) ndr_pull_$e->{TYPE}));\n";
	} else {
		pidl "\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));\n";
	}
	if (my $range = util::has_property($e, "range")) {
		my ($low, $high) = split(/ /, $range, 2);
		pidl "\tif ($var_prefix$e->{NAME} < $low || $var_prefix$e->{NAME} > $high) {\n";
		pidl "\t\treturn ndr_pull_error(ndr, NDR_ERR_RANGE, \"value out of range\");\n\t}\n";
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
		pidl "\tif ($var_prefix$e->{NAME}) {\n";
		if (util::has_property($e, "relative")) {
			pidl "\t\tNDR_CHECK(ndr_push_relative2(ndr, $var_prefix$e->{NAME}));\n";
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
			pidl "\tNDR_CHECK(ndr_push_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_push_flags_fn_t) ndr_push_$e->{TYPE}));\n";
		}
	} elsif ($e->{POINTERS}) {
		pidl "\t\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, NDR_SCALARS|NDR_BUFFERS, $cprefix$var_prefix$e->{NAME}));\n";
	} else {
		pidl "\t\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));\n";
	}

	if (need_wire_pointer($e)) {
		pidl "\t}\n";
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
		pidl "\tif ($var_prefix$e->{NAME}) {\n";
	}
	    
	if (util::array_size($e)) {
		ParseArrayPrint($e, $var_prefix)
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPrintSwitch($e, $var_prefix, $switch);
	} else {
		pidl "\t\tndr_print_$e->{TYPE}(ndr, \"$e->{NAME}\", $cprefix$var_prefix$e->{NAME});\n";
	}

	if (need_wire_pointer($e)) {
		pidl "\t}\n";
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
		pidl "\tif ($var_prefix$e->{NAME}) {\n";
		if (util::has_property($e, "relative")) {
			pidl "\t\tstruct ndr_pull_save _relative_save;\n";
			pidl "\t\tndr_pull_save(ndr, &_relative_save);\n";
			pidl "\t\tNDR_CHECK(ndr_pull_relative2(ndr, $var_prefix$e->{NAME}));\n";
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
			pidl "\tNDR_CHECK(ndr_pull_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_flags_fn_t) ndr_pull_$e->{TYPE}));\n";
		}
	} elsif ($e->{POINTERS}) {
		pidl "\t\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, NDR_SCALARS|NDR_BUFFERS, $cprefix$var_prefix$e->{NAME}));\n";
	} else {
		pidl "\t\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));\n";
	}

	if (need_wire_pointer($e)) {
		if (util::has_property($e, "relative")) {
			pidl "\t\tndr_pull_restore(ndr, &_relative_save);\n";
		}
		pidl "\t}\n";
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
		my $size = find_size_var($e, util::array_size($e), "r->");
		$e->{CONFORMANT_SIZE} = $size;
		check_null_pointer($size);
		pidl "\tNDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, $size));\n";
	}

	if (defined $e->{TYPE} && $e->{TYPE} eq "string" 
	    &&  util::property_matches($e, "flag", ".*LIBNDR_FLAG_STR_CONFORMANT.*")) {
		pidl "\tNDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ndr_string_array_size(ndr, r->$e->{NAME})));\n";
	}

	pidl "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";

	pidl "\tNDR_CHECK(ndr_push_struct_start(ndr));\n";

	my $align = struct_alignment($struct);
	pidl "\tNDR_CHECK(ndr_push_align(ndr, $align));\n";

	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPushScalar($e, "r->", "NDR_SCALARS");
	}	

	pidl "buffers:\n";
	pidl "\tif (!(ndr_flags & NDR_BUFFERS)) goto done;\n";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPushBuffer($e, "r->", "NDR_BUFFERS");
	}

	pidl "\tndr_push_struct_end(ndr);\n";

	pidl "done:\n";

	end_flags($struct);
}


#####################################################################
# generate a push function for an enum
sub ParseEnumPush($)
{
	my($enum) = shift;
	my($type_fn) = util::enum_type_fn($enum);

	start_flags($enum);

	pidl "\tNDR_CHECK(ndr_push_$type_fn(ndr, NDR_SCALARS, r));\n";

	end_flags($enum);
}

#####################################################################
# generate a pull function for an enum
sub ParseEnumPull($)
{
	my($enum) = shift;
	my($type_fn) = util::enum_type_fn($enum);
	my($type_v_decl) = util::map_type(util::enum_type_fn($enum));

	pidl "\t$type_v_decl v;\n";
	start_flags($enum);
	pidl "\tNDR_CHECK(ndr_pull_$type_fn(ndr, NDR_SCALARS, &v));\n";
	pidl "\t*r = v;\n";

	end_flags($enum);
}

#####################################################################
# generate a print function for an enum
sub ParseEnumPrint($)
{
	my($enum) = shift;

	pidl "\tconst char *val = NULL;\n\n";

	start_flags($enum);

	pidl "\tswitch (r) {\n";
	my $els = \@{$enum->{ELEMENTS}};
	foreach my $i (0 .. $#{$els}) {
		my $e = ${$els}[$i];
		chomp $e;
		if ($e =~ /^(.*)=/) {
			$e = $1;
		}
		pidl "\t\tcase $e: val = \"$e\"; break;\n";
	}

	pidl "\t}\n\n\tndr_print_enum(ndr, name, \"$enum->{TYPE}\", val, r);\n";

	end_flags($enum);
}


#####################################################################
# generate a push function for a bitmap
sub ParseBitmapPush($)
{
	my($bitmap) = shift;
	my($type_fn) = util::bitmap_type_fn($bitmap);

	start_flags($bitmap);

	pidl "\tNDR_CHECK(ndr_push_$type_fn(ndr, NDR_SCALARS, r));\n";

	end_flags($bitmap);
}

#####################################################################
# generate a pull function for an bitmap
sub ParseBitmapPull($)
{
	my($bitmap) = shift;
	my($type_fn) = util::bitmap_type_fn($bitmap);
	my($type_decl) = util::bitmap_type_decl($bitmap);

	pidl "\t$type_decl v;\n";
	start_flags($bitmap);
	pidl "\tNDR_CHECK(ndr_pull_$type_fn(ndr, NDR_SCALARS, &v));\n";
	pidl "\t*r = v;\n";

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

	pidl "\tndr_print_bitmap_flag(ndr, sizeof($type_decl), \"$flag\", $flag, r);\n";
}

#####################################################################
# generate a print function for an bitmap
sub ParseBitmapPrint($)
{
	my($bitmap) = shift;
	my($type_decl) = util::bitmap_type_decl($bitmap);
	my($type_fn) = util::bitmap_type_fn($bitmap);

	start_flags($bitmap);

	pidl "\tndr_print_$type_fn(ndr, name, r);\n";

	pidl "\tndr->depth++;\n";
	foreach my $e (@{$bitmap->{ELEMENTS}}) {
		ParseBitmapPrintElement($e, $bitmap);
	}
	pidl "\tndr->depth--;\n";

	end_flags($bitmap);
}

#####################################################################
# generate a struct print function
sub ParseStructPrint($)
{
	my($struct) = shift;

	if (! defined $struct->{ELEMENTS}) {
		return;
	}

	start_flags($struct);

	pidl "\tndr->depth++;\n";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPrintScalar($e, "r->");
	}
	pidl "\tndr->depth--;\n";

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
		pidl "\tuint32_t _conformant_size;\n";
		$conform_e->{CONFORMANT_SIZE} = "_conformant_size";
	}

	# declare any internal pointers we need
	foreach my $e (@{$struct->{ELEMENTS}}) {
		if (need_wire_pointer($e)) {
			pidl "\tuint32_t _ptr_$e->{NAME};\n";
		}
	}

	start_flags($struct);

	pidl "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";

	pidl "\tNDR_CHECK(ndr_pull_struct_start(ndr));\n";

	if (defined $conform_e) {
		pidl "\tNDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &$conform_e->{CONFORMANT_SIZE}));\n";
	}

	my $align = struct_alignment($struct);
	pidl "\tNDR_CHECK(ndr_pull_align(ndr, $align));\n";

	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPullScalar($e, "r->", "NDR_SCALARS");
	}	

	pidl "buffers:\n";
	pidl "\tif (!(ndr_flags & NDR_BUFFERS)) goto done;\n";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPullBuffer($e, "r->", "NDR_BUFFERS");
	}

	foreach my $e (@{$struct->{ELEMENTS}}) {
		CheckArraySizes($e, "r->");
	}

	pidl "\tndr_pull_struct_end(ndr);\n";

	pidl "done:\n";

	end_flags($struct);
}

#####################################################################
# calculate size of ndr struct
sub ParseStructNdrSize($)
{
	my $t = shift;
	my $static = fn_prefix($t);
	my $sizevar;

	pidl "size_t ndr_size_$t->{NAME}(const struct $t->{NAME} *r, int flags)\n";
	pidl "{\n";
	if (my $flags = util::has_property($t, "flag")) {
		pidl "\tflags |= $flags;\n";
	}
	pidl "\treturn ndr_size_struct(r, flags, (ndr_push_flags_fn_t)ndr_push_$t->{NAME});\n";
	pidl "}\n\n";
}

#####################################################################
# calculate size of ndr struct
sub ParseUnionNdrSize($)
{
	my $t = shift;
	my $static = fn_prefix($t);
	my $sizevar;

	pidl "size_t ndr_size_$t->{NAME}(const union $t->{NAME} *r, int level, int flags)\n";
	pidl "{\n";
	if (my $flags = util::has_property($t, "flag")) {
		pidl "\tflags |= $flags;\n";
	}
	pidl "\treturn ndr_size_union(r, flags, level, (ndr_push_union_fn_t)ndr_push_$t->{NAME});\n";
	pidl "}\n\n";
}

#####################################################################
# parse a union - push side
sub ParseUnionPush($)
{
	my $e = shift;
	my $have_default = 0;

	start_flags($e);

	pidl "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";

	pidl "\tNDR_CHECK(ndr_push_struct_start(ndr));\n";

#	my $align = union_alignment($e);
#	pidl "\tNDR_CHECK(ndr_push_align(ndr, $align));\n";

	pidl "\tswitch (level) {\n";
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			pidl "\tdefault:\n";
			$have_default = 1;
		} else {
			pidl "\tcase $el->{PROPERTIES}->{case}:\n";
		}
		if ($el->{TYPE} ne "EMPTY") {
			ParseElementPushScalar($el, "r->", "NDR_SCALARS");
		}
		pidl "\tbreak;\n\n";
	}
	if (! $have_default) {
		pidl "\tdefault:\n";
		pidl "\t\treturn ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);\n";
	}
	pidl "\t}\n";
	pidl "buffers:\n";
	pidl "\tif (!(ndr_flags & NDR_BUFFERS)) goto done;\n";
	pidl "\tswitch (level) {\n";
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			pidl "\tdefault:\n";
		} else {
			pidl "\tcase $el->{PROPERTIES}->{case}:\n";
		}
		if ($el->{TYPE} ne "EMPTY") {
			ParseElementPushBuffer($el, "r->", "NDR_BUFFERS");
		}
		pidl "\tbreak;\n\n";
	}
	if (! $have_default) {
		pidl "\tdefault:\n";
		pidl "\t\treturn ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);\n";
	}
	pidl "\t}\n";
	pidl "\tndr_push_struct_end(ndr);\n";
	pidl "done:\n";
	end_flags($e);
}

#####################################################################
# print a union
sub ParseUnionPrint($)
{
	my $e = shift;
	my $have_default = 0;

	start_flags($e);

	pidl "\tswitch (level) {\n";
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			$have_default = 1;
			pidl "\tdefault:\n";
		} else {
			pidl "\tcase $el->{PROPERTIES}->{case}:\n";
		}
		if ($el->{TYPE} ne "EMPTY") {
			ParseElementPrintScalar($el, "r->");
		}
		pidl "\tbreak;\n\n";
	}
	if (! $have_default) {
		pidl "\tdefault:\n\t\tndr_print_bad_level(ndr, name, level);\n";
	}
	pidl "\t}\n";

	end_flags($e);
}

#####################################################################
# parse a union - pull side
sub ParseUnionPull($)
{
	my $e = shift;
	my $have_default = 0;

	start_flags($e);

	pidl "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";

	pidl "\tNDR_CHECK(ndr_pull_struct_start(ndr));\n";

#	my $align = union_alignment($e);
#	pidl "\tNDR_CHECK(ndr_pull_align(ndr, $align));\n";

	pidl "\tswitch (level) {\n";
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			pidl "\tdefault: {\n";
			$have_default = 1;
		} else {
			pidl "\tcase $el->{PROPERTIES}->{case}: {\n";
		}
		if ($el->{TYPE} ne "EMPTY") {
			if ($el->{POINTERS}) {
				pidl "\t\tuint32_t _ptr_$el->{NAME};\n";
			}
			ParseElementPullScalar($el, "r->", "NDR_SCALARS");
		}
		pidl "\tbreak; }\n\n";
	}
	if (! $have_default) {
		pidl "\tdefault:\n";
		pidl "\t\treturn ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);\n";
	}
	pidl "\t}\n";
	pidl "buffers:\n";
	pidl "\tif (!(ndr_flags & NDR_BUFFERS)) goto done;\n";
	pidl "\tswitch (level) {\n";
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			pidl "\tdefault:\n";
		} else {
			pidl "\tcase $el->{PROPERTIES}->{case}:\n";
		}
		if ($el->{TYPE} ne "EMPTY") {
			ParseElementPullBuffer($el, "r->", "NDR_BUFFERS");
		}
		pidl "\tbreak;\n\n";
	}
	if (! $have_default) {
		pidl "\tdefault:\n";
		pidl "\t\treturn ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);\n";
	}
	pidl "\t}\n";
	pidl "\tndr_pull_struct_end(ndr);\n";
	pidl "done:\n";
	end_flags($e);
}


#####################################################################
# parse a type
sub ParseTypePush($)
{
	my($data) = shift;

	($data->{TYPE} eq "STRUCT") &&
	    ParseStructPush($data);
	($data->{TYPE} eq "UNION") &&
	    ParseUnionPush($data);
	($data->{TYPE} eq "ENUM") &&
	    ParseEnumPush($data);
	($data->{TYPE} eq "BITMAP") &&
	    ParseBitmapPush($data);
}

#####################################################################
# generate a print function for a type
sub ParseTypePrint($)
{
	my($data) = shift;

	($data->{TYPE} eq "STRUCT") &&
	    ParseStructPrint($data);
	($data->{TYPE} eq "UNION") &&
	    ParseUnionPrint($data);
	($data->{TYPE} eq "ENUM") &&
	    ParseEnumPrint($data);
	($data->{TYPE} eq "BITMAP") &&
	    ParseBitmapPrint($data);
}

#####################################################################
# parse a type
sub ParseTypePull($)
{
	my($data) = shift;

	($data->{TYPE} eq "STRUCT") &&
	    ParseStructPull($data);
	($data->{TYPE} eq "UNION") &&
	    ParseUnionPull($data);
	($data->{TYPE} eq "ENUM") &&
	    ParseEnumPull($data);
	($data->{TYPE} eq "BITMAP") &&
	    ParseBitmapPull($data);
}

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

	if (defined($e->{PROPERTIES}) && !defined($e->{DATA}->{PROPERTIES})) {
		$e->{DATA}->{PROPERTIES} = $e->{PROPERTIES};
	}

	if ($e->{DATA}->{TYPE} eq "STRUCT") {
		pidl $static . "NTSTATUS ndr_push_$e->{NAME}(struct ndr_push *ndr, int ndr_flags, struct $e->{NAME} *r)";
		pidl "\n{\n";
		ParseTypePush($e->{DATA});
		pidl "\treturn NT_STATUS_OK;\n";
		pidl "}\n\n";
	}

	if ($e->{DATA}->{TYPE} eq "UNION") {
		pidl $static . "NTSTATUS ndr_push_$e->{NAME}(struct ndr_push *ndr, int ndr_flags, int level, union $e->{NAME} *r)";
		pidl "\n{\n";
		ParseTypePush($e->{DATA});
		pidl "\treturn NT_STATUS_OK;\n";
		pidl "}\n\n";
	}

	if ($e->{DATA}->{TYPE} eq "ENUM") {
		pidl $static . "NTSTATUS ndr_push_$e->{NAME}(struct ndr_push *ndr, int ndr_flags, enum $e->{NAME} r)";
		pidl "\n{\n";
		ParseTypePush($e->{DATA});
		pidl "\treturn NT_STATUS_OK;\n";
		pidl "}\n\n";
	}

	if ($e->{DATA}->{TYPE} eq "BITMAP") {
		my $type_decl = util::bitmap_type_decl($e->{DATA});
		pidl $static . "NTSTATUS ndr_push_$e->{NAME}(struct ndr_push *ndr, int ndr_flags, $type_decl r)";
		pidl "\n{\n";
		ParseTypePush($e->{DATA});
		pidl "\treturn NT_STATUS_OK;\n";
		pidl "}\n\n";
	}
}


#####################################################################
# parse a typedef - pull side
sub ParseTypedefPull($)
{
	my($e) = shift;
	my $static = fn_prefix($e);

	if (defined($e->{PROPERTIES}) && !defined($e->{DATA}->{PROPERTIES})) {
		$e->{DATA}->{PROPERTIES} = $e->{PROPERTIES};
	}

	if (! needed::is_needed("pull_$e->{NAME}")) {
#		print "pull_$e->{NAME} not needed\n";
		return;
	}

	if ($e->{DATA}->{TYPE} eq "STRUCT") {
		pidl $static . "NTSTATUS ndr_pull_$e->{NAME}(struct ndr_pull *ndr, int ndr_flags, struct $e->{NAME} *r)";
		pidl "\n{\n";
		ParseTypePull($e->{DATA});
		pidl "\treturn NT_STATUS_OK;\n";
		pidl "}\n\n";
	}

	if ($e->{DATA}->{TYPE} eq "UNION") {
		pidl $static . "NTSTATUS ndr_pull_$e->{NAME}(struct ndr_pull *ndr, int ndr_flags, int level, union $e->{NAME} *r)";
		pidl "\n{\n";
		ParseTypePull($e->{DATA});
		pidl "\treturn NT_STATUS_OK;\n";
		pidl "}\n\n";
	}

	if ($e->{DATA}->{TYPE} eq "ENUM") {
		pidl $static . "NTSTATUS ndr_pull_$e->{NAME}(struct ndr_pull *ndr, int ndr_flags, enum $e->{NAME} *r)";
		pidl "\n{\n";
		ParseTypePull($e->{DATA});
		pidl "\treturn NT_STATUS_OK;\n";
		pidl "}\n\n";
	}

	if ($e->{DATA}->{TYPE} eq "BITMAP") {
		my $type_decl = util::bitmap_type_decl($e->{DATA});
		pidl $static . "NTSTATUS ndr_pull_$e->{NAME}(struct ndr_pull *ndr, int ndr_flags, $type_decl *r)";
		pidl "\n{\n";
		ParseTypePull($e->{DATA});
		pidl "\treturn NT_STATUS_OK;\n";
		pidl "}\n\n";
	}
}


#####################################################################
# parse a typedef - print side
sub ParseTypedefPrint($)
{
	my($e) = shift;

	if (defined($e->{PROPERTIES}) && !defined($e->{DATA}->{PROPERTIES})) {
		$e->{DATA}->{PROPERTIES} = $e->{PROPERTIES};
	}

	if ($e->{DATA}->{TYPE} eq "STRUCT") {
		pidl "void ndr_print_$e->{NAME}(struct ndr_print *ndr, const char *name, struct $e->{NAME} *r)";
		pidl "\n{\n";
		pidl "\tndr_print_struct(ndr, name, \"$e->{NAME}\");\n";
		ParseTypePrint($e->{DATA});
		pidl "}\n\n";
	}

	if ($e->{DATA}->{TYPE} eq "UNION") {
		pidl "void ndr_print_$e->{NAME}(struct ndr_print *ndr, const char *name, int level, union $e->{NAME} *r)";
		pidl "\n{\n";
		pidl "\tndr_print_union(ndr, name, level, \"$e->{NAME}\");\n";
		ParseTypePrint($e->{DATA});
		pidl "}\n\n";
	}

	if ($e->{DATA}->{TYPE} eq "ENUM") {
		pidl "void ndr_print_$e->{NAME}(struct ndr_print *ndr, const char *name, enum $e->{NAME} r)";
		pidl "\n{\n";
		ParseTypePrint($e->{DATA});
		pidl "}\n\n";
	}

	if ($e->{DATA}->{TYPE} eq "BITMAP") {
		my $type_decl = util::bitmap_type_decl($e->{DATA});
		pidl "void ndr_print_$e->{NAME}(struct ndr_print *ndr, const char *name, $type_decl r)";
		pidl "\n{\n";
		ParseTypePrint($e->{DATA});
		pidl "}\n\n";
	}
}

#####################################################################
## calculate the size of a structure
sub ParseTypedefNdrSize($)
{
	my($t) = shift;
	if (! needed::is_needed("ndr_size_$t->{NAME}")) {
		return;
	}
	
	($t->{DATA}->{TYPE} eq "STRUCT") &&
		ParseStructNdrSize($t);

	($t->{DATA}->{TYPE} eq "UNION") &&
		ParseUnionNdrSize($t);
}

#####################################################################
# parse a function - print side
sub ParseFunctionPrint($)
{
	my($fn) = shift;

	pidl "void ndr_print_$fn->{NAME}(struct ndr_print *ndr, const char *name, int flags, struct $fn->{NAME} *r)";
	pidl "\n{\n";
	pidl "\tndr_print_struct(ndr, name, \"$fn->{NAME}\");\n";
	pidl "\tndr->depth++;\n";

	pidl "\tif (flags & NDR_SET_VALUES) {\n";
	pidl "\t\tndr->flags |= LIBNDR_PRINT_SET_VALUES;\n";
	pidl "\t}\n";

	pidl "\tif (flags & NDR_IN) {\n";
	pidl "\t\tndr_print_struct(ndr, \"in\", \"$fn->{NAME}\");\n";
	pidl "\tndr->depth++;\n";

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "in")) {
			ParseElementPrintScalar($e, "r->in.");
		}
	}
	pidl "\tndr->depth--;\n";
	pidl "\t}\n";
	
	pidl "\tif (flags & NDR_OUT) {\n";
	pidl "\t\tndr_print_struct(ndr, \"out\", \"$fn->{NAME}\");\n";
	pidl "\tndr->depth++;\n";
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "out")) {
			ParseElementPrintScalar($e, "r->out.");
		}
	}
	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		my $cprefix = "&";
		$cprefix = "" if (is_scalar_type($fn->{RETURN_TYPE})) ; # FIXME: Should really use util::c_push_prefix here
		pidl "\tndr_print_$fn->{RETURN_TYPE}(ndr, \"result\", $cprefix"."r->out.result);\n";
	}
	pidl "\tndr->depth--;\n";
	pidl "\t}\n";
	
	pidl "\tndr->depth--;\n";
	pidl "}\n\n";
}


#####################################################################
# parse a function element
sub ParseFunctionElementPush($$)
{ 
	my $e = shift;
	my $inout = shift;

	if (util::array_size($e)) {
		if (need_wire_pointer($e)) {
			pidl "\tNDR_CHECK(ndr_push_ptr(ndr, r->$inout.$e->{NAME}));\n";
			pidl "\tif (r->$inout.$e->{NAME}) {\n";
			ParseArrayPush($e, "r->$inout.", "NDR_SCALARS|NDR_BUFFERS");
			pidl "\t}\n";
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

	pidl $static . "NTSTATUS ndr_push_$fn->{NAME}(struct ndr_push *ndr, int flags, struct $fn->{NAME} *r)\n{\n";

	pidl "\n\tif (!(flags & NDR_IN)) goto ndr_out;\n\n";

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "in")) {
			ParseFunctionElementPush($e, "in");
		}		
	}

	pidl "\nndr_out:\n";
	pidl "\tif (!(flags & NDR_OUT)) goto done;\n\n";

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "out")) {
			ParseFunctionElementPush($e, "out");
		}		
	}

	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		pidl "\tNDR_CHECK(ndr_push_$fn->{RETURN_TYPE}(ndr, NDR_SCALARS, r->out.result));\n";
	}
    
	pidl "\ndone:\n";
	pidl "\n\treturn NT_STATUS_OK;\n}\n\n";
}

#####################################################################
# parse a function element
sub ParseFunctionElementPull($$)
{ 
	my $e = shift;
	my $inout = shift;

	if (util::array_size($e)) {
		if (need_wire_pointer($e)) {
			pidl "\tNDR_CHECK(ndr_pull_ptr(ndr, &_ptr_$e->{NAME}));\n";
			pidl "\tr->$inout.$e->{NAME} = NULL;\n";
			pidl "\tif (_ptr_$e->{NAME}) {\n";
		} elsif ($inout eq "out" && util::has_property($e, "ref")) {
			pidl "\tif (r->$inout.$e->{NAME}) {\n";
		} else {
			pidl "\t{\n";
		}
		ParseArrayPull($e, "r->$inout.", "NDR_SCALARS|NDR_BUFFERS");
		pidl "\t}\n";
	} else {
		if ($inout eq "out" && util::has_property($e, "ref")) {
			pidl "\tif (ndr->flags & LIBNDR_FLAG_REF_ALLOC) {\n";
			pidl "\tNDR_ALLOC(ndr, r->out.$e->{NAME});\n";
			pidl "\t}\n";
		}
		if ($inout eq "in" && util::has_property($e, "ref")) {
			pidl "\tNDR_ALLOC(ndr, r->in.$e->{NAME});\n";
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
		pidl "\tNDR_ALLOC(ndr, r->out.$e->{NAME});\n";
		if (util::has_property($e, "in")) {
			pidl "\t*r->out.$e->{NAME} = *r->in.$e->{NAME};\n";
		} else {
			pidl "\tZERO_STRUCTP(r->out.$e->{NAME});\n";
		}
		return;
	}

	# its an array
	my $size = find_size_var($e, $asize, "r->out.");
	check_null_pointer($size);
	pidl "\tNDR_ALLOC_N(ndr, r->out.$e->{NAME}, $size);\n";
	if (util::has_property($e, "in")) {
		pidl "\tmemcpy(r->out.$e->{NAME},r->in.$e->{NAME},$size * sizeof(*r->in.$e->{NAME}));\n";
	} else {
		pidl "\tmemset(r->out.$e->{NAME}, 0, $size * sizeof(*r->out.$e->{NAME}));\n";
	}
}


#####################################################################
# parse a function
sub ParseFunctionPull($)
{ 
	my($fn) = shift;
	my $static = fn_prefix($fn);

	# pull function args
	pidl $static . "NTSTATUS ndr_pull_$fn->{NAME}(struct ndr_pull *ndr, int flags, struct $fn->{NAME} *r)\n{\n";

	# declare any internal pointers we need
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (need_wire_pointer($e)) {
			pidl "\tuint32_t _ptr_$e->{NAME};\n";
		}
	}

	pidl "\n\tif (!(flags & NDR_IN)) goto ndr_out;\n\n";

	# auto-init the out section of a structure. I originally argued that
	# this was a bad idea as it hides bugs, but coping correctly
	# with initialisation and not wiping ref vars is turning
	# out to be too tricky (tridge)
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "out")) {
			pidl "\tZERO_STRUCT(r->out);\n\n";
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

	pidl "\nndr_out:\n";
	pidl "\tif (!(flags & NDR_OUT)) goto done;\n\n";

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
		pidl "\tNDR_CHECK(ndr_pull_$fn->{RETURN_TYPE}(ndr, NDR_SCALARS, &r->out.result));\n";
	}

	pidl "\ndone:\n";
	pidl "\n\treturn NT_STATUS_OK;\n}\n\n";
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

	pidl "static const struct dcerpc_interface_call $interface->{NAME}\_calls[] = {\n";
	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") {
			pidl "\t{\n";
			pidl "\t\t\"$d->{NAME}\",\n";
			pidl "\t\tsizeof(struct $d->{NAME}),\n";
			pidl "\t\t(ndr_push_flags_fn_t) ndr_push_$d->{NAME},\n";
			pidl "\t\t(ndr_pull_flags_fn_t) ndr_pull_$d->{NAME},\n";
			pidl "\t\t(ndr_print_function_t) ndr_print_$d->{NAME}\n";
			pidl "\t},\n";
		}
	}
	pidl "\t{ NULL, 0, NULL, NULL, NULL }\n};\n\n";

	# If no endpoint is set, default to the interface name as a named pipe
	if (! defined $interface->{PROPERTIES}->{endpoint}) {
		$interface->{PROPERTIES}->{endpoint} = "\"ncacn_np:[\\\\pipe\\\\" . $interface->{NAME} . "]\"";
	}

	my @e = split / /, $interface->{PROPERTIES}->{endpoint};
	my $endpoint_count = $#e + 1;

	pidl "static const char * const $interface->{NAME}\_endpoint_strings[] = {\n";
	foreach my $ep (@e) {
		pidl "\t$ep, \n";
	}
	pidl "};\n\n";

	pidl "static const struct dcerpc_endpoint_list $interface->{NAME}\_endpoints = {\n";
	pidl "\t$endpoint_count, $interface->{NAME}\_endpoint_strings\n";
	pidl "};\n\n";

	pidl "\nconst struct dcerpc_interface_table dcerpc_table_$interface->{NAME} = {\n";
	pidl "\t\"$interface->{NAME}\",\n";
	pidl "\tDCERPC_$uname\_UUID,\n";
	pidl "\tDCERPC_$uname\_VERSION,\n";
	pidl "\tDCERPC_$uname\_HELPSTRING,\n";
	pidl "\t$count,\n";
	pidl "\t$interface->{NAME}\_calls,\n";
	pidl "\t&$interface->{NAME}\_endpoints\n";
	pidl "};\n\n";

	pidl "static NTSTATUS dcerpc_ndr_$interface->{NAME}_init(void)\n";
	pidl "{\n";
	pidl "\treturn librpc_register_interface(&dcerpc_table_$interface->{NAME});\n";
	pidl "}\n\n";
}

#####################################################################
# parse the interface definitions
sub ParseInterface($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};

	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "DECLARE") {
		    $typedefs{$d->{NAME}} = $d;
		}
		if ($d->{TYPE} eq "TYPEDEF") {
		    $typedefs{$d->{NAME}} = $d;
		}
	}

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
	pidl "NTSTATUS dcerpc_$basename\_init(void)\n";
	pidl "{\n";
	pidl "\tNTSTATUS status = NT_STATUS_OK;\n";
	foreach my $interface (@{$idl}) {
		next if $interface->{TYPE} ne "INTERFACE";

		my $data = $interface->{INHERITED_DATA};
		my $count = 0;
		foreach my $d (@{$data}) {
			if ($d->{TYPE} eq "FUNCTION") { $count++; }
		}

		next if ($count == 0);

		pidl "\tstatus = dcerpc_ndr_$interface->{NAME}_init();\n";
		pidl "\tif (NT_STATUS_IS_ERR(status)) {\n";
		pidl "\t\treturn status;\n";
		pidl "\t}\n\n";
	}
	pidl "\treturn status;\n";
	pidl "}\n\n";
}

#####################################################################
# parse a parsed IDL structure back into an IDL file
sub Parse($$)
{
	my($idl) = shift;
	my($filename) = shift;
	my $h_filename = $filename;
	$res = "";

	if ($h_filename =~ /(.*)\.c/) {
		$h_filename = "$1.h";
	}

	pidl "/* parser auto-generated by pidl */\n\n";
	pidl "#include \"includes.h\"\n";
	pidl "#include \"$h_filename\"\n\n";

	foreach my $x (@{$idl}) {
		if ($x->{TYPE} eq "INTERFACE") { 
			needed::BuildNeeded($x);
			ParseInterface($x);
		}
	}

	RegistrationFunction($idl, $filename);

	return $res;
}

1;
