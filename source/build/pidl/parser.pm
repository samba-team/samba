###################################################
# Samba4 parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# Copyright jelmer@samba.org 2004
# released under the GNU GPL

package IdlParser;

use strict;
use client;

# the list of needed functions
my %needed;
my %structs;

sub pidl($)
{
	print OUT shift;
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
		for my $e2 (@{$fn->{DATA}}) {
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
# work out is a parse function should be declared static or not
sub fn_prefix($)
{
	my $fn = shift;
	if ($fn->{TYPE} eq "TYPEDEF") {
		if (util::has_property($fn->{DATA}, "public")) {
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
# work out the correct alignment for a structure
sub struct_alignment
{
	my $s = shift;

	my $align = 1;
	for my $e (@{$s->{ELEMENTS}}) {
		my $a = 1;

		if (!util::need_wire_pointer($e)
		    && defined $structs{$e->{TYPE}}) {
			if ($structs{$e->{TYPE}}->{DATA}->{TYPE} eq "STRUCT") {
				$a = struct_alignment($structs{$e->{TYPE}}->{DATA});
			} elsif ($structs{$e->{TYPE}}->{DATA}->{TYPE} eq "UNION") {
				if (defined $structs{$e->{TYPE}}->{DATA}) {
					$a = union_alignment($structs{$e->{TYPE}}->{DATA});
				}
			}
		} else {
			$a = util::type_align($e);
		}

		if ($align < $a) {
			$align = $a;
		}
	}

	return $align;
}

#####################################################################
# work out the correct alignment for a union
sub union_alignment
{
	my $u = shift;

	my $align = 1;

	foreach my $e (@{$u->{DATA}}) {
		my $a = 1;

		if ($e->{TYPE} eq "EMPTY") {
			next;
		}

		if (!util::need_wire_pointer($e)
		    && defined $structs{$e->{DATA}->{TYPE}}) {
			my $s = $structs{$e->{DATA}->{TYPE}};
			if ($s->{DATA}->{TYPE} eq "STRUCT") {
				$a = struct_alignment($s->{DATA});
			} elsif ($s->{DATA}->{TYPE} eq "UNION") {
				$a = union_alignment($s->{DATA});
			}
		} else {
			$a = util::type_align($e->{DATA});
		}

		if ($align < $a) {
			$align = $a;
		}
	}

	return $align;
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
		pidl "\t\tNDR_CHECK(ndr_push_uint32(ndr, $size));\n";
	}

	if (my $length = util::has_property($e, "length_is")) {
		$length = find_size_var($e, $length, $var_prefix);
		pidl "\t\tNDR_CHECK(ndr_push_uint32(ndr, 0));\n";
		pidl "\t\tNDR_CHECK(ndr_push_uint32(ndr, $length));\n";
		$size = $length;
	}

	if (util::is_scalar_type($e->{TYPE})) {
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

	if (util::is_scalar_type($e->{TYPE})) {
		pidl "\t\tndr_print_array_$e->{TYPE}(ndr, \"$e->{NAME}\", $var_prefix$e->{NAME}, $size);\n";
	} else {
		pidl "\t\tndr_print_array(ndr, \"$e->{NAME}\", $var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_print_fn_t)ndr_print_$e->{TYPE});\n";
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

		pidl "\tif ($size > $alloc_size) {\n";
		pidl "\t\treturn ndr_pull_error(ndr, NDR_ERR_CONFORMANT_SIZE, \"Bad conformant size %u should be %u\", $alloc_size, $size);\n";
		pidl "\t}\n";
	} elsif (!util::is_inline_array($e)) {
		if ($var_prefix =~ /^r->out/ && $size =~ /^\*r->in/) {
			my $size2 = substr($size, 1);
			pidl "if (ndr->flags & LIBNDR_FLAG_REF_ALLOC) {	NDR_ALLOC(ndr, $size2); }\n";
		}

		# non fixed arrays encode the size just before the array
		pidl "\t{\n";
		pidl "\t\tuint32_t _array_size;\n";
		pidl "\t\tNDR_CHECK(ndr_pull_uint32(ndr, &_array_size));\n";
		if ($size =~ /r->in/) {
			pidl "\t\tif (!(ndr->flags & LIBNDR_FLAG_REF_ALLOC) && _array_size != $size) {\n";
		} else {
			pidl "\t\tif ($size != _array_size) {\n";
		}
		pidl "\t\t\treturn ndr_pull_error(ndr, NDR_ERR_ARRAY_SIZE, \"Bad array size %u should be %u\", _array_size, $size);\n";
		pidl "\t\t}\n";
		if ($size =~ /r->in/) {
			pidl "else { $size = _array_size; }\n";
		}
		pidl "\t}\n";
	}

	if ((util::need_alloc($e) && !util::is_fixed_array($e)) ||
	    ($var_prefix eq "r->in." && util::has_property($e, "ref"))) {
		if (!util::is_inline_array($e) || $ndr_flags eq "NDR_SCALARS") {
			pidl "\t\tNDR_ALLOC_N(ndr, $var_prefix$e->{NAME}, MAX(1, $alloc_size));\n";
		}
	}

	if (($var_prefix eq "r->out." && util::has_property($e, "ref"))) {
		if (!util::is_inline_array($e) || $ndr_flags eq "NDR_SCALARS") {
			pidl "\tif (ndr->flags & LIBNDR_FLAG_REF_ALLOC) {";
			pidl "\t\tNDR_ALLOC_N(ndr, $var_prefix$e->{NAME}, MAX(1, $alloc_size));\n";
			pidl "\t}\n";
		}
	}

	pidl "\t{\n";

	if (my $length = util::has_property($e, "length_is")) {
		$length = find_size_var($e, $length, $var_prefix);
		pidl "\t\tuint32_t _offset, _length;\n";
		pidl "\t\tNDR_CHECK(ndr_pull_uint32(ndr, &_offset));\n";
		pidl "\t\tNDR_CHECK(ndr_pull_uint32(ndr, &_length));\n";
		pidl "\t\tif (_offset != 0) return ndr_pull_error(ndr, NDR_ERR_OFFSET, \"Bad array offset 0x%08x\", _offset);\n";
		pidl "\t\tif (_length > $size || _length != $length) return ndr_pull_error(ndr, NDR_ERR_LENGTH, \"Bad array length 0x%08x > size 0x%08x\", _offset, $size);\n\n";
		$size = "_length";
	}

	if (util::is_scalar_type($e->{TYPE})) {
		pidl "\t\tNDR_CHECK(ndr_pull_array_$e->{TYPE}(ndr, $ndr_flags, $var_prefix$e->{NAME}, $size));\n";
	} else {
		pidl "\t\tNDR_CHECK(ndr_pull_array(ndr, $ndr_flags, (void **)$var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_pull_flags_fn_t)ndr_pull_$e->{TYPE}));\n";
	}

	pidl "\t}\n";
}


#####################################################################
# parse scalars in a structure element
sub ParseElementPushScalar($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $cprefix = util::c_push_prefix($e);
	my $sub_size = util::has_property($e, "subcontext");

	start_flags($e);

	if (my $value = util::has_property($e, "value")) {
		pidl "\t$cprefix$var_prefix$e->{NAME} = $value;\n";
	}

	if (util::has_property($e, "relative")) {
		pidl "\tNDR_CHECK(ndr_push_relative1(ndr, $var_prefix$e->{NAME}));\n";
	} elsif (util::is_inline_array($e)) {
		ParseArrayPush($e, "r->", "NDR_SCALARS");
	} elsif (util::need_wire_pointer($e)) {
		pidl "\tNDR_CHECK(ndr_push_ptr(ndr, $var_prefix$e->{NAME}));\n";
	} elsif (util::need_alloc($e)) {
		# no scalar component
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPushSwitch($e, $var_prefix, $ndr_flags, $switch);
	} elsif (defined $sub_size) {
		if (util::is_builtin_type($e->{TYPE})) {
			pidl "\tNDR_CHECK(ndr_push_subcontext_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_push_fn_t) ndr_push_$e->{TYPE}));\n";
		} else {
			pidl "\tNDR_CHECK(ndr_push_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_push_flags_fn_t) ndr_push_$e->{TYPE}));\n";
		}
	} elsif (util::is_builtin_type($e->{TYPE})) {
		pidl "\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $cprefix$var_prefix$e->{NAME}));\n";
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
	my $cprefix = util::c_push_prefix($e);

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
	} elsif (util::has_direct_buffers($e)) {
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

	my $cprefix = util::c_pull_prefix($e);

	my $utype = $structs{$e->{TYPE}};
	if (!defined $utype ||
	    !util::has_property($utype->{DATA}, "nodiscriminant")) {
		my $e2 = find_sibling($e, $switch);
		pidl "\tif (($ndr_flags) & NDR_SCALARS) {\n";
		pidl "\t\t $e2->{TYPE} _level;\n";
		pidl "\t\tNDR_CHECK(ndr_pull_$e2->{TYPE}(ndr, &_level));\n";
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
	my $cprefix = util::c_push_prefix($e);

	my $utype = $structs{$e->{TYPE}};
	if (!defined $utype ||
	    !util::has_property($utype->{DATA}, "nodiscriminant")) {
		my $e2 = find_sibling($e, $switch);
		pidl "\tif (($ndr_flags) & NDR_SCALARS) {\n";
		pidl "\t\tNDR_CHECK(ndr_push_$e2->{TYPE}(ndr, $switch_var));\n";
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
	my $cprefix = util::c_push_prefix($e);

	pidl "\tndr_print_$e->{TYPE}(ndr, \"$e->{NAME}\", $switch_var, $cprefix$var_prefix$e->{NAME});\n";
}


#####################################################################
# parse scalars in a structure element - pull size
sub ParseElementPullScalar($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $cprefix = util::c_pull_prefix($e);
	my $sub_size = util::has_property($e, "subcontext");

	start_flags($e);

	if (util::is_inline_array($e)) {
		ParseArrayPull($e, "r->", "NDR_SCALARS");
	} elsif (util::need_wire_pointer($e)) {
		pidl "\tNDR_CHECK(ndr_pull_ptr(ndr, &_ptr_$e->{NAME}));\n";
		pidl "\tif (_ptr_$e->{NAME}) {\n";
		pidl "\t\tNDR_ALLOC(ndr, $var_prefix$e->{NAME});\n";
		if (util::has_property($e, "relative")) {
			pidl "\t\tNDR_CHECK(ndr_pull_relative1(ndr, $var_prefix$e->{NAME}, _ptr_$e->{NAME}));";
		}
		pidl "\t} else {\n";
		pidl "\t\t$var_prefix$e->{NAME} = NULL;\n";
		pidl "\t}\n";
	} elsif (util::need_alloc($e)) {
		# no scalar component
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPullSwitch($e, $var_prefix, $ndr_flags, $switch);
	} elsif (defined $sub_size) {
		if (util::is_builtin_type($e->{TYPE})) {
			pidl "\tNDR_CHECK(ndr_pull_subcontext_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_fn_t) ndr_pull_$e->{TYPE}));\n";
		} else {
			pidl "\tNDR_CHECK(ndr_pull_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_flags_fn_t) ndr_pull_$e->{TYPE}));\n";
		}
	} elsif (util::is_builtin_type($e->{TYPE})) {
		pidl "\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $cprefix$var_prefix$e->{NAME}));\n";
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
	my $cprefix = util::c_push_prefix($e);
	my $sub_size = util::has_property($e, "subcontext");

	if (util::is_pure_scalar($e)) {
		return;
	}

	start_flags($e);

	if (util::need_wire_pointer($e)) {
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
			if (util::is_builtin_type($e->{TYPE})) {
				pidl "\tNDR_CHECK(ndr_push_subcontext_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_push_fn_t) ndr_push_$e->{TYPE}));\n";
			} else {
				pidl "\tNDR_CHECK(ndr_push_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_push_flags_fn_t) ndr_push_$e->{TYPE}));\n";
			}
		}
	} elsif (util::is_builtin_type($e->{TYPE})) {
		pidl "\t\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $cprefix$var_prefix$e->{NAME}));\n";
	} elsif ($e->{POINTERS}) {
		pidl "\t\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, NDR_SCALARS|NDR_BUFFERS, $cprefix$var_prefix$e->{NAME}));\n";
	} else {
		pidl "\t\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));\n";
	}

	if (util::need_wire_pointer($e)) {
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
	my $cprefix = util::c_push_prefix($e);

	if (util::need_wire_pointer($e)) {
		pidl "\tif ($var_prefix$e->{NAME}) {\n";
	}
	    
	if (util::array_size($e)) {
		ParseArrayPrint($e, $var_prefix)
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPrintSwitch($e, $var_prefix, $switch);
	} else {
		pidl "\t\tndr_print_$e->{TYPE}(ndr, \"$e->{NAME}\", $cprefix$var_prefix$e->{NAME});\n";
	}

	if (util::need_wire_pointer($e)) {
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
	my $cprefix = util::c_pull_prefix($e);
	my $sub_size = util::has_property($e, "subcontext");

	if (util::is_pure_scalar($e)) {
		return;
	}

	start_flags($e);

	if (util::need_wire_pointer($e)) {
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
			if (util::is_builtin_type($e->{TYPE})) {
				pidl "\tNDR_CHECK(ndr_pull_subcontext_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_fn_t) ndr_pull_$e->{TYPE}));\n";
			} else {
				pidl "\tNDR_CHECK(ndr_pull_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_flags_fn_t) ndr_pull_$e->{TYPE}));\n";
			}
		}
	} elsif (util::is_builtin_type($e->{TYPE})) {
		pidl "\t\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $cprefix$var_prefix$e->{NAME}));\n";
	} elsif ($e->{POINTERS}) {
		pidl "\t\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, NDR_SCALARS|NDR_BUFFERS, $cprefix$var_prefix$e->{NAME}));\n";
	} else {
		pidl "\t\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));\n";
	}

	if (util::need_wire_pointer($e)) {
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
	my $conform_e;
	
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
		$conform_e = $e;
		pidl "\tNDR_CHECK(ndr_push_uint32(ndr, $size));\n";
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
		pidl "\tuint32_t _conformant_size;\n";
		$conform_e->{CONFORMANT_SIZE} = "_conformant_size";
	}

	# declare any internal pointers we need
	foreach my $e (@{$struct->{ELEMENTS}}) {
		if (util::need_wire_pointer($e)) {
			pidl "\tuint32_t _ptr_$e->{NAME};\n";
		}
	}

	start_flags($struct);

	pidl "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";

	pidl "\tNDR_CHECK(ndr_pull_struct_start(ndr));\n";

	if (defined $conform_e) {
		pidl "\tNDR_CHECK(ndr_pull_uint32(ndr, &$conform_e->{CONFORMANT_SIZE}));\n";
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

	pidl $static . "size_t ndr_size_$t->{NAME}(int ret, struct $t->{NAME} *r, int flags)\n";
	pidl "{\n";

	if (util::has_property($t->{DATA}, "flag")) {
		
		pidl "\tflags = flags | " . $t->{DATA}->{PROPERTIES}->{flag} . ";\n";	
	}

	pidl "\tif(!r) return 0;\n";

	pidl "\tret = NDR_SIZE_ALIGN(ret, " . struct_alignment($t->{DATA}) . ", flags);\n";

	for my $e (@{$t->{DATA}->{ELEMENTS}}) {
		my $switch = "";

		if (util::has_property($e, "subcontext")) {
			pidl "\tret += $e->{PROPERTIES}->{subcontext}; /* Subcontext length */\n";
		}

		if (util::has_property($e, "switch_is")) {
			$switch = ", r->$e->{PROPERTIES}->{switch_is}";
		}

		if ($e->{POINTERS} > 0) {
			pidl "\tret = ndr_size_ptr(ret, &r->$e->{NAME}, flags); \n";
		} elsif (util::is_inline_array($e)) {
			$sizevar = find_size_var($e, util::array_size($e), "r->");
			pidl "\t{\n";
			pidl "\t\tint i;\n";
			pidl "\t\tfor(i = 0; i < $sizevar; i++) {\n";
			pidl "\t\t\tret = ndr_size_$e->{TYPE}(ret, &r->" . $e->{NAME} . "[i], flags);\n";
			pidl "\t\t}\n";
			pidl "\t}\n";
		} else {
			pidl "\tret = ndr_size_$e->{TYPE}(ret, &r->$e->{NAME}$switch, flags); \n";
		}
	}
	
	# Add lengths of relative members
	for my $e (@{$t->{DATA}->{ELEMENTS}}) {
		next unless (util::has_property($e, "relative"));

		pidl "\tif (r->$e->{NAME}) {\n";
		pidl "\t\tret = ndr_size_$e->{TYPE}(ret, r->$e->{NAME}, flags); \n"; 
		pidl "\t}\n";
	}

	pidl "\treturn ret;\n";
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
	foreach my $el (@{$e->{DATA}}) {
		if ($el->{CASE} eq "default") {
			pidl "\tdefault:\n";
			$have_default = 1;
		} else {
			pidl "\tcase $el->{CASE}:\n";
		}
		if ($el->{TYPE} eq "UNION_ELEMENT") {
			ParseElementPushScalar($el->{DATA}, "r->", "NDR_SCALARS");
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
	foreach my $el (@{$e->{DATA}}) {
		if ($el->{CASE} eq "default") {
			pidl "\tdefault:\n";
		} else {
			pidl "\tcase $el->{CASE}:\n";
		}
		if ($el->{TYPE} eq "UNION_ELEMENT") {
			ParseElementPushBuffer($el->{DATA}, "r->", "NDR_BUFFERS");
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
	foreach my $el (@{$e->{DATA}}) {
		if ($el->{CASE} eq "default") {
			$have_default = 1;
			pidl "\tdefault:\n";
		} else {
			pidl "\tcase $el->{CASE}:\n";
		}
		if ($el->{TYPE} eq "UNION_ELEMENT") {
			ParseElementPrintScalar($el->{DATA}, "r->");
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
	foreach my $el (@{$e->{DATA}}) {
		if ($el->{CASE} eq "default") {
			pidl "\tdefault: {\n";
			$have_default = 1;
		} else {
			pidl "\tcase $el->{CASE}: {\n";
		}
		if ($el->{TYPE} eq "UNION_ELEMENT") {
			my $e2 = $el->{DATA};
			if ($e2->{POINTERS}) {
				pidl "\t\tuint32_t _ptr_$e2->{NAME};\n";
			}
			ParseElementPullScalar($el->{DATA}, "r->", "NDR_SCALARS");
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
	foreach my $el (@{$e->{DATA}}) {
		if ($el->{CASE} eq "default") {
			pidl "\tdefault:\n";
		} else {
			pidl "\tcase $el->{CASE}:\n";
		}
		if ($el->{TYPE} eq "UNION_ELEMENT") {
			ParseElementPullBuffer($el->{DATA}, "r->", "NDR_BUFFERS");
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
# calculate size of ndr union

sub ParseUnionNdrSize($)
{
	my $t = shift;
	my $static = fn_prefix($t);

	pidl $static . "size_t ndr_size_$t->{NAME}(int ret, union $t->{NAME} *data, uint16 level, int flags)\n";
	pidl "{\n";
	if (util::has_property($t->{DATA}, "flag")) {
		pidl "\tflags = flags | " . $t->{DATA}->{PROPERTIES}->{flag} . ";\n";	
	}
	pidl "\tif(!data) return 0;\n\n";
	
	pidl "\tret = NDR_SIZE_ALIGN(ret, " . union_alignment($t->{DATA}) . ", flags);\n";

	pidl "\tswitch(level) {\n";

	for my $e (@{$t->{DATA}->{DATA}}) {
		if ($e->{TYPE} eq "UNION_ELEMENT") {
			
			if ($e->{CASE} eq "default") {
				pidl "\t\tdefault:";
			} else { 
				pidl "\t\tcase $e->{CASE}:";
			}
			
			pidl " return ndr_size_$e->{DATA}->{TYPE}(ret, &data->$e->{DATA}->{NAME}, flags); \n";

		}
	}
	pidl "\t}\n";
	pidl "\treturn ret;\n";
	pidl "}\n\n";
}

#####################################################################
# parse a type
sub ParseTypePush($)
{
	my($data) = shift;

	if (ref($data) eq "HASH") {
		($data->{TYPE} eq "STRUCT") &&
		    ParseStructPush($data);
		($data->{TYPE} eq "UNION") &&
		    ParseUnionPush($data);
	}
}

#####################################################################
# generate a print function for a type
sub ParseTypePrint($)
{
	my($data) = shift;

	if (ref($data) eq "HASH") {
		($data->{TYPE} eq "STRUCT") &&
		    ParseStructPrint($data);
		($data->{TYPE} eq "UNION") &&
		    ParseUnionPrint($data);
	}
}

#####################################################################
# parse a type
sub ParseTypePull($)
{
	my($data) = shift;

	if (ref($data) eq "HASH") {
		($data->{TYPE} eq "STRUCT") &&
		    ParseStructPull($data);
		($data->{TYPE} eq "UNION") &&
		    ParseUnionPull($data);
	}
}

#####################################################################
# parse a typedef - push side
sub ParseTypedefPush($)
{
	my($e) = shift;
	my $static = fn_prefix($e);

	if (! $needed{"push_$e->{NAME}"}) {
#		print "push_$e->{NAME} not needed\n";
		return;
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
}


#####################################################################
# parse a typedef - pull side
sub ParseTypedefPull($)
{
	my($e) = shift;
	my $static = fn_prefix($e);

	if (! $needed{"pull_$e->{NAME}"}) {
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
}


#####################################################################
# parse a typedef - print side
sub ParseTypedefPrint($)
{
	my($e) = shift;

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
}

#####################################################################
## calculate the size of a structure
sub ParseTypedefNdrSize($)
{
	my($t) = shift;
	if (! $needed{"ndr_size_$t->{NAME}"}) {
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
	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "in")) {
			ParseElementPrintScalar($e, "r->in.");
		}
	}
	pidl "\tndr->depth--;\n";
	pidl "\t}\n";
	
	pidl "\tif (flags & NDR_OUT) {\n";
	pidl "\t\tndr_print_struct(ndr, \"out\", \"$fn->{NAME}\");\n";
	pidl "\tndr->depth++;\n";
	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "out")) {
			ParseElementPrintScalar($e, "r->out.");
		}
	}
	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		if (util::is_scalar_type($fn->{RETURN_TYPE})) {
			pidl "\tndr_print_$fn->{RETURN_TYPE}(ndr, \"result\", r->out.result);\n";
		} else {
			pidl "\tndr_print_$fn->{RETURN_TYPE}(ndr, \"result\", &r->out.result);\n";
		}
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
		if (util::need_wire_pointer($e)) {
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
	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "in")) {
			ParseFunctionElementPush($e, "in");
		}		
	}

	pidl "\nndr_out:\n";
	pidl "\tif (!(flags & NDR_OUT)) goto done;\n\n";
	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "out")) {
			ParseFunctionElementPush($e, "out");
		}		
	}

	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		pidl "\tNDR_CHECK(ndr_push_$fn->{RETURN_TYPE}(ndr, r->out.result));\n";
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
		if (util::need_wire_pointer($e)) {
			pidl "\tNDR_CHECK(ndr_pull_ptr(ndr, &_ptr_$e->{NAME}));\n";
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
	pidl "\tNDR_ALLOC_N(ndr, r->out.$e->{NAME}, MAX(1, $size));\n";
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
	foreach my $e (@{$fn->{DATA}}) {
		if (util::need_wire_pointer($e)) {
			pidl "\tuint32_t _ptr_$e->{NAME};\n";
		}
	}

	pidl "\n\tif (!(flags & NDR_IN)) goto ndr_out;\n\n";

	# auto-init the out section of a structure. I originally argued that
	# this was a bad idea as it hides bugs, but coping correctly
	# with initialisation and not wiping ref vars is turning
	# out to be too tricky (tridge)
	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "out")) {
			pidl "\tZERO_STRUCT(r->out);\n\n";
			last;
		}
	}

	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "in")) {
			ParseFunctionElementPull($e, "in");
		}
		# we need to allocate any reference output variables, so that
		# a dcerpc backend can be sure they are non-null
		if (util::has_property($e, "out") && util::has_property($e, "ref")) {
			AllocateRefVars($e);
		}
	}

	pidl "\nndr_out:\n";
	pidl "\tif (!(flags & NDR_OUT)) goto done;\n\n";
	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "out")) {
			ParseFunctionElementPull($e, "out");
		}
	}

	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		pidl "\tNDR_CHECK(ndr_pull_$fn->{RETURN_TYPE}(ndr, &r->out.result));\n";
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

	if ($count == 0) {
		return;
	}

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
	pidl "\t{ NULL, 0, NULL, NULL }\n};\n\n";

	my $endpoints;

	if (! defined $interface->{PROPERTIES}->{endpoints}) {
		$interface->{PROPERTIES}->{endpoints} = $interface->{NAME};
	}

	my @e = split / /, $interface->{PROPERTIES}->{endpoints};
	my $endpoint_count = $#e + 1;

	pidl "static const char * const $interface->{NAME}\_endpoint_strings[] = {\n\t";
	for (my $i=0; $i < $#e; $i++) {
		pidl "\"$e[$i]\", ";
	}
	pidl "\"$e[$#e]\"\n";
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
}


#####################################################################
# parse the interface definitions
sub ParseInterface($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};

	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "TYPEDEF") {
		    $structs{$d->{NAME}} = $d;
	    }
	}

	foreach my $d (@{$data}) {
		($d->{TYPE} eq "TYPEDEF") && 
			ParseTypedefNdrSize($d);
	}

	foreach my $d (@{$data}) {
		($d->{TYPE} eq "TYPEDEF") &&
		    ParseTypedefPush($d);
		($d->{TYPE} eq "FUNCTION") && 
		    ParseFunctionPush($d);
	}
	foreach my $d (@{$data}) {
		($d->{TYPE} eq "TYPEDEF") &&
		    ParseTypedefPull($d);
		($d->{TYPE} eq "FUNCTION") && 
		    ParseFunctionPull($d);
	}
	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "TYPEDEF" &&
		    !util::has_property($d->{DATA}, "noprint")) {
			ParseTypedefPrint($d);
		}
		if ($d->{TYPE} eq "FUNCTION" &&
		    !util::has_property($d, "noprint")) {
			ParseFunctionPrint($d);
		}
	}

	FunctionTable($interface);

}

sub NeededFunction($)
{
	my $fn = shift;
	$needed{"pull_$fn->{NAME}"} = 1;
	$needed{"push_$fn->{NAME}"} = 1;
	foreach my $e (@{$fn->{DATA}}) {
		$e->{PARENT} = $fn;
		$needed{"pull_$e->{TYPE}"} = 1;
		$needed{"push_$e->{TYPE}"} = 1;
	}
}

sub NeededTypedef($)
{
	my $t = shift;
	if (util::has_property($t->{DATA}, "public")) {
		$needed{"pull_$t->{NAME}"} = 1;
		$needed{"push_$t->{NAME}"} = 1;		
	}

	if ($t->{DATA}->{TYPE} eq "STRUCT") {
		if (util::has_property($t->{DATA}, "gensize")) {
			$needed{"ndr_size_$t->{NAME}"} = 1;
		}

		for my $e (@{$t->{DATA}->{ELEMENTS}}) {
			$e->{PARENT} = $t->{DATA};
			if ($needed{"pull_$t->{NAME}"}) {
				$needed{"pull_$e->{TYPE}"} = 1;
			}
			if ($needed{"push_$t->{NAME}"}) {
				$needed{"push_$e->{TYPE}"} = 1;
			}
			if ($needed{"ndr_size_$t->{NAME}"}) {
				$needed{"ndr_size_$e->{TYPE}"} = 1;
			}
		}
	}
	if ($t->{DATA}->{TYPE} eq "UNION") {
		for my $e (@{$t->{DATA}->{DATA}}) {
			$e->{PARENT} = $t->{DATA};
			if ($e->{TYPE} eq "UNION_ELEMENT") {
				if ($needed{"pull_$t->{NAME}"}) {
					$needed{"pull_$e->{DATA}->{TYPE}"} = 1;
				}
				if ($needed{"push_$t->{NAME}"}) {
					$needed{"push_$e->{DATA}->{TYPE}"} = 1;
				}
				if ($needed{"ndr_size_$t->{NAME}"}) {
					$needed{"ndr_size_$e->{DATA}->{TYPE}"} = 1;
				}
			}
		}
	}
}

#####################################################################
# work out what parse functions are needed
sub BuildNeeded($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};
	foreach my $d (@{$data}) {
		($d->{TYPE} eq "FUNCTION") && 
		    NeededFunction($d);
	}
	foreach my $d (reverse @{$data}) {
		($d->{TYPE} eq "TYPEDEF") &&
		    NeededTypedef($d);
	}
}

#####################################################################
# parse a parsed IDL structure back into an IDL file
sub Parse($$)
{
	my($idl) = shift;
	my($filename) = shift;

	open(OUT, ">$filename") || die "can't open $filename";    

	pidl "/* parser auto-generated by pidl */\n\n";
	pidl "#include \"includes.h\"\n\n";
	foreach my $x (@{$idl}) {
		if ($x->{TYPE} eq "INTERFACE") { 
			BuildNeeded($x);
			ParseInterface($x);
		}
	}

	pidl IdlClient::Parse($idl);

	close(OUT);
}

1;
