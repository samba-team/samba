###################################################
# Samba4 parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# released under the GNU GPL

package IdlEParser;

use strict;
use client;
use Data::Dumper;

# the list of needed functions
my %needed;
my %structs;

my $module = "samr";
my $if_uuid;
my $if_version;
my $if_endpoints;

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
		pidl "\t{ guint32 _flags_save_$e->{TYPE} = flags;\n";
		pidl "\tflags |= $flags;\n";
	}
}

###################################################################
# end any special flags for an element or structure
sub end_flags($)
{
	my $e = shift;
	my $flags = util::has_property($e, "flag");
	if (defined $flags) {
		pidl "\tflags = _flags_save_$e->{TYPE};\n\t}\n";
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
		pidl "\t\toffset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_array_size, NULL);\n";
	}

	if (my $length = util::has_property($e, "length_is")) {
		$length = find_size_var($e, $length, $var_prefix);
		pidl "\t\toffset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_length_is, NULL);\n";
		pidl "\t\toffset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_length_is, NULL);\n";
		$size = $length;
	}

	if (util::is_scalar_type($e->{TYPE})) {
		pidl "\t\t// ndr_push_array_$e->{TYPE}(ndr, $ndr_flags, $var_prefix$e->{NAME}, $size);\n";
	} else {
		pidl "\t\t// ndr_push_array(ndr, $ndr_flags, $var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_push_flags_fn_t)ndr_push_$e->{TYPE});\n";
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
			pidl "if (flags & LIBNDR_FLAG_REF_ALLOC) {	NDR_ALLOC(ndr, $size2); }\n";
		}

		# non fixed arrays encode the size just before the array
		pidl "\t{\n";
		pidl "\t\tuint32_t _array_size;\n";
		pidl "\t\t(ndr_pull_uint32(ndr, &_array_size);\n";
		if ($size =~ /r->in/) {
			pidl "\t\tif (!(flags & LIBNDR_FLAG_REF_ALLOC) && _array_size != $size) {\n";
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
			pidl "\tif (flags & LIBNDR_FLAG_REF_ALLOC) {";
			pidl "\t\tNDR_ALLOC_N(ndr, $var_prefix$e->{NAME}, MAX(1, $alloc_size));\n";
			pidl "\t}\n";
		}
	}

	pidl "\t{\n";

	if (my $length = util::has_property($e, "length_is")) {
		$length = find_size_var($e, $length, $var_prefix);
		pidl "\t\tuint32_t _offset, _length;\n";
		pidl "\t\tndr_pull_uint32(ndr, &_offset);\n";
		pidl "\t\tndr_pull_uint32(ndr, &_length);\n";
		pidl "\t\tif (_offset != 0) return ndr_pull_error(ndr, NDR_ERR_OFFSET, \"Bad array offset 0x%08x\", _offset);\n";
		pidl "\t\tif (_length > $size || _length != $length) return ndr_pull_error(ndr, NDR_ERR_LENGTH, \"Bad array length 0x%08x > size 0x%08x\", _offset, $size);\n\n";
		$size = "_length";
	}

	if (util::is_scalar_type($e->{TYPE})) {
		pidl "\t\tndr_pull_array_$e->{TYPE}(ndr, $ndr_flags, $var_prefix$e->{NAME}, $size);\n";
	} else {
		pidl "\t\tndr_pull_array(ndr, $ndr_flags, (void **)$var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_pull_flags_fn_t)ndr_pull_$e->{TYPE});\n";
	}

	pidl "\t}\n";
}
sub ParamPolicyHandle($)
{
    my($p) = shift;
    my($res);

    $res .= "\toffset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_policy_handle, NULL, NULL, FALSE, FALSE);\n";

    return $res;
}


sub ParamString($)
{
    my($p) = shift;
    my($res);

    $res .= "\toffset = dissect_ndr_pointer_cb(tvb, offset, pinfo, tree, drep, dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE, \"$p->{NAME}\", hf_$p->{NAME}_string, cb_wstr_postprocess, GINT_TO_POINTER(1));\n";

    return $res;
}

sub ParamDomSID($)
{
    my($p) = shift;
    my($res);

    $res .= "\toffset = dissect_ndr_nt_SID(tvb, offset, pinfo, tree, drep);\n";

    return $res;
}

my %param_handlers = (
		      'policy_handle' => \&ParamPolicyHandle,
		      'string' => \&ParamString,
		      'dom_sid2'      => \&ParamDomSID,
		      );

####################################################################
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
		pidl "\tndr_push_relative(ndr, NDR_SCALARS, $var_prefix$e->{NAME}, (ndr_push_const_fn_t) ndr_push_$e->{TYPE});\n";
	} elsif (util::is_inline_array($e)) {
		ParseArrayPush($e, "r->", "NDR_SCALARS");
	} elsif (util::need_wire_pointer($e)) {
	    pidl "\toffset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_ptr, &ptr);\n";
	} elsif (util::need_alloc($e)) {
		# no scalar component
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPushSwitch($e, $var_prefix, $ndr_flags, $switch);
	} elsif (defined $sub_size) {
		if (util::is_builtin_type($e->{TYPE})) {
			pidl "\tndr_push_subcontext_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_push_fn_t) ndr_push_$e->{TYPE});\n";
		} else {
			pidl "\tndr_push_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_push_flags_fn_t) ndr_push_$e->{TYPE});\n";
		}
	} elsif (util::is_builtin_type($e->{TYPE})) {
		pidl "\toffset = dissect_ndr_$e->{TYPE}(tvb, offset, pinfo, tree, drep, hf_$e->{NAME}_$e->{TYPE}, NULL);\n";
	} else {
	    if (defined($param_handlers{$e->{TYPE}})) {
		pidl &{$param_handlers{$e->{TYPE}}}($e);
	    } else {
		pidl "\tproto_tree_add_text(tree, tvb, offset, -1, \"Unhandled IDL type '$e->{TYPE}'\");\n";
	    }
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
		pidl "\tif (flags & LIBNDR_PRINT_SET_VALUES) {\n";
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
		pidl "\t\tndr_pull_$e2->{TYPE}(ndr, &_level);\n";
		if ($switch_var =~ /r->in/) {
			pidl "\t\tif (!(flags & LIBNDR_FLAG_REF_ALLOC) && _level != $switch_var) {\n";
		} else {
			pidl "\t\tif (_level != $switch_var) {\n";
		}
		pidl "\t\t\treturn ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value %u in $e->{NAME}\");\t\t}\n";
		if ($switch_var =~ /r->/) {
			pidl "else { $switch_var = _level; }\n";
		}
		pidl "\t}\n";
	}

	my $sub_size = util::has_property($e, "subcontext");
	if (defined $sub_size) {
		pidl "\tndr_pull_subcontext_union_fn(ndr, $sub_size, $switch_var, $cprefix$var_prefix$e->{NAME}, (ndr_pull_union_fn_t) ndr_pull_$e->{TYPE});\n";
	} else {
		pidl "\tndr_pull_$e->{TYPE}(ndr, $ndr_flags, $switch_var, $cprefix$var_prefix$e->{NAME});\n";
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
		pidl "\t\toffset = dissect_ndr_$e2->{TYPE}(tvb, offset, pinfo, tree, drep, hf_switch, NULL);\n";
		pidl "\t}\n";
	}

	my $sub_size = util::has_property($e, "subcontext");
	if (defined $sub_size) {
		pidl "\tndr_push_subcontext_union_fn(ndr, $sub_size, $switch_var, $cprefix$var_prefix$e->{NAME}, (ndr_push_union_fn_t) ndr_push_$e->{TYPE});\n";
	} else {
	    if (defined($param_handlers{$e->{TYPE}})) {
		pidl &{$param_handlers{$e->{TYPE}}}($e);
	    } else {
		pidl "\tproto_tree_add_text(tree, tvb, offset, -1, \"Unhandled IDL type '$e->{TYPE}'\");\n";
	    }
#		pidl "\tndr_push_$e->{TYPE}(ndr, $ndr_flags, $switch_var, $cprefix$var_prefix$e->{NAME});\n";
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

	if (util::has_property($e, "relative")) {
		pidl "\tndr_pull_relative(ndr, (const void **)&$var_prefix$e->{NAME}, sizeof(*$var_prefix$e->{NAME}), (ndr_pull_flags_fn_t)ndr_pull_$e->{TYPE});\n";
	} elsif (util::is_inline_array($e)) {
		ParseArrayPull($e, "r->", "NDR_SCALARS");
	} elsif (util::need_wire_pointer($e)) {
		pidl "\tndr_pull_uint32(ndr, &_ptr_$e->{NAME});\n";
		pidl "\tif (_ptr_$e->{NAME}) {\n";
		pidl "\t\tNDR_ALLOC(ndr, $var_prefix$e->{NAME});\n";
		pidl "\t} else {\n";
		pidl "\t\t$var_prefix$e->{NAME} = NULL;\n";
		pidl "\t}\n";
	} elsif (util::need_alloc($e)) {
		# no scalar component
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPullSwitch($e, $var_prefix, $ndr_flags, $switch);
	} elsif (defined $sub_size) {
		if (util::is_builtin_type($e->{TYPE})) {
			pidl "\tndr_pull_subcontext_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_fn_t) ndr_pull_$e->{TYPE});\n";
		} else {
			pidl "\tndr_pull_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_flags_fn_t) ndr_pull_$e->{TYPE});\n";
		}
	} elsif (util::is_builtin_type($e->{TYPE})) {
		pidl "\tndr_pull_$e->{TYPE}(ndr, $cprefix$var_prefix$e->{NAME});\n";
	} else {
		pidl "\tndr_pull_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME});\n";
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
		pidl "\tif (ptr) {\n";
	}
	    
	if (util::has_property($e, "relative")) {
		pidl "\tndr_push_relative(ndr, NDR_BUFFERS, $cprefix$var_prefix$e->{NAME}, (ndr_push_const_fn_t) ndr_push_$e->{TYPE});\n";
	} elsif (util::is_inline_array($e)) {
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
				pidl "\tndr_push_subcontext_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_push_fn_t) ndr_push_$e->{TYPE});\n";
			} else {
				pidl "\tndr_push_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_push_flags_fn_t) ndr_push_$e->{TYPE});\n";
			}
		}
	} elsif (util::is_builtin_type($e->{TYPE})) {
		pidl "\toffset = dissect_ndr_$e->{TYPE}(tvb, offset, pinfo, tree, drep, hf_$e->{NAME}_$e->{TYPE}, NULL);\n";
	} elsif ($e->{POINTERS}) {
	    if (defined($param_handlers{$e->{TYPE}})) {
		pidl &{$param_handlers{$e->{TYPE}}}($e);
	    } else {
		pidl "\t\toffset = dissect_$e->{TYPE}(tvb, offset, pinfo, tree, drep, NDR_SCALARS|NDR_BUFFERS);\n";
	    }
	} else {
	    if (defined($param_handlers{$e->{TYPE}})) {
		pidl &{$param_handlers{$e->{TYPE}}}($e);
	    } else {
		pidl "\t\toffset = dissect__$e->{TYPE}(tvb, offset, pinfo, tree, drep, $ndr_flags);\n";
	    }
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
		ParseArrayPrint($e, $var_prefix);
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

	if (util::has_property($e, "relative")) {
		return;
	}

	start_flags($e);

	if (util::need_wire_pointer($e)) {
		pidl "\tif ($var_prefix$e->{NAME}) {\n";
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
				pidl "\tndr_pull_subcontext_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_fn_t) ndr_pull_$e->{TYPE});\n";
			} else {
				pidl "\tndr_pull_subcontext_flags_fn(ndr, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_flags_fn_t) ndr_pull_$e->{TYPE});\n";
			}
		}
	} elsif (util::is_builtin_type($e->{TYPE})) {
		pidl "\t\tndr_pull_$e->{TYPE}(ndr, $cprefix$var_prefix$e->{NAME});\n";
	} elsif ($e->{POINTERS}) {
		pidl "\t\tndr_pull_$e->{TYPE}(ndr, NDR_SCALARS|NDR_BUFFERS, $cprefix$var_prefix$e->{NAME});\n";
	} else {
		pidl "\t\tndr_pull_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME});\n";
	}

	if (util::need_wire_pointer($e)) {
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
		pidl "\tndr_push_uint32(ndr, $size);\n";
	}

	pidl "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";

	pidl "\tndr_push_struct_start(ndr);\n";

	my $align = struct_alignment($struct);
	pidl "\tndr_push_align(ndr, $align);\n";

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
		if (util::need_wire_pointer($e) &&
		    !util::has_property($e, "relative")) {
			pidl "\tuint32_t _ptr_$e->{NAME};\n";
		}
	}

	start_flags($struct);

	pidl "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";

	pidl "\tndr_pull_struct_start(ndr);\n";

	if (defined $conform_e) {
		pidl "\tndr_pull_uint32(ndr, &$conform_e->{CONFORMANT_SIZE});\n";
	}

	my $align = struct_alignment($struct);
	pidl "\tndr_pull_align(ndr, $align);\n";

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
# parse a union - push side
sub ParseUnionPush($)
{
	my $e = shift;
	my $have_default = 0;

	start_flags($e);

	pidl "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";

	pidl "\tndr_push_struct_start(ndr);\n";

#	my $align = union_alignment($e);
#	pidl "\tndr_push_align(ndr, $align);\n";

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
# parse a union - pull side
sub ParseUnionPull($)
{
	my $e = shift;
	my $have_default = 0;

	start_flags($e);

	pidl "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";

	pidl "\tndr_pull_struct_start(ndr);\n";

#	my $align = union_alignment($e);
#	pidl "\tndr_pull_align(ndr, $align);\n";

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
# parse a typedef
sub ParseTypedefEthereal($)
{
	my($e) = shift;
	my $static = fn_prefix($e);

	if ($e->{DATA}->{TYPE} eq "STRUCT") {
	    pidl $static . "int dissect_$e->{NAME}(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int flags)\n";
	    pidl "\n{\n";
#		ParseTypePush($e->{DATA});
	    pidl "\treturn offset;\n";
	    pidl "}\n\n";
	}

	if ($e->{DATA}->{TYPE} eq "UNION") {
	    pidl $static . "int dissect_$e->{NAME}(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int flags)\n";
		pidl "\n{\n";
#		ParseTypePush($e->{DATA});
	    pidl "\treturn offset;\n";
		pidl "}\n\n";
	}
}


#####################################################################
# parse a function element
sub ParseFunctionElementPush($$)
{ 
	my $e = shift;
	my $inout = shift;

	if (util::array_size($e)) {
		if (util::need_wire_pointer($e)) {
		    pidl "\toffset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_ptr, &ptr);\n";
		    pidl "\tif (ptr) {\n";
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
sub ParseFunctionEthereal($)
{ 
	my($fn) = shift;
	my $static = fn_prefix($fn);

	# Comment displaying IDL for this function
	
	pidl "/*\n\n";
	pidl IdlDump::DumpFunction($fn);
	pidl "*/\n\n";

	# Request

	pidl $static . "int $fn->{NAME}_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)\n";
	pidl "{\n";
	pidl "\tint flags = NDR_SCALARS|NDR_BUFFERS;\n\n";
	pidl "\tguint32 ptr;\n\n";

	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "in")) {
			ParseFunctionElementPush($e, "in");
		}		
	}

	pidl "\n\treturn offset;\n";
	pidl "}\n\n";

	# Response

	pidl $static . "int $fn->{NAME}_resp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)\n";
	pidl "{\n";
	pidl "\tint flags = NDR_SCALARS|NDR_BUFFERS;\n\n";
	pidl "\tguint32 ptr;\n\n";

	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "out")) {
			ParseFunctionElementPush($e, "out");
		}		
	}

	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
	    if ($fn->{RETURN_TYPE} eq "NTSTATUS") {
		pidl "\n\toffset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, hf_rc, NULL);\n";
	    } else {
		pidl "\tproto_tree_add_text(tree, tvb, offset, -1, \"Unhandled return type '$fn->{RETURN_TYPE}'\");\n";
	    }
	}

	pidl "\n\treturn offset;\n";
	pidl "}\n\n";
}

#####################################################################
# produce a function call table
sub FunctionTable($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};
	my $count = 0;
	my $uname = uc $interface->{NAME};

	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") { $count++; }
	}

	if ($count == 0) {
		return;
	}

	pidl "static dcerpc_sub_dissector dcerpc_dissectors[] = {\n";
	my $num = 0;
	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") {
		    # Strip module name from function name, if present
		    my($n) = $d->{NAME};
		    $n = substr($d->{NAME}, length($module) + 1),
		        if $module eq substr($d->{NAME}, 0, length($module));
		    pidl "\t{ $num, \"$n\",\n";
		    pidl "\t\t$d->{NAME}_rqst,\n";
		    pidl "\t\t$d->{NAME}_resp },\n";
		    $num++;
		}
	}
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
		    ParseTypedefEthereal($d);
		($d->{TYPE} eq "FUNCTION") && 
		    ParseFunctionEthereal($d);
	}

	FunctionTable($interface);
}

# Convert an idl type to an ethereal FT_* type

sub type2ft($)
{
    my($t) = shift;

    return "FT_UINT32", if ($t eq "uint32");
    return "FT_UINT16", if ($t eq "uint16");
    return "FT_BYTES";
}

# Select an ethereal BASE_* type for an idl type

sub type2base($)
{
    my($t) = shift;

    return "BASE_DEC", if ($t eq "uint32") or ($t eq "uint16");
    return "BASE_NONE";
}

sub NeededFunction($)
{
	my $fn = shift;
	$needed{"pull_$fn->{NAME}"} = 1;
	$needed{"push_$fn->{NAME}"} = 1;
	foreach my $e (@{$fn->{DATA}}) {
	    $needed{"hf_$e->{NAME}_$e->{TYPE}"} = {
		'name' => $e->{NAME},
		'type' => $e->{TYPE},
		'ft'   => type2ft($e->{TYPE}),
		'base' => type2base($e->{TYPE})
		};
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
		for my $e (@{$t->{DATA}->{ELEMENTS}}) {
			$e->{PARENT} = $t->{DATA};
			if ($needed{"pull_$t->{NAME}"}) {
				$needed{"pull_$e->{TYPE}"} = 1;
			}
			if ($needed{"push_$t->{NAME}"}) {
				$needed{"push_$e->{TYPE}"} = 1;
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
# parse the interface definitions
sub ModuleHeader($)
{
    my($h) = shift;

    $if_uuid = $h->{PROPERTIES}->{uuid};
    $if_version = $h->{PROPERTIES}->{version};
    $if_endpoints = $h->{PROPERTIES}->{endpoints};
}

#####################################################################
# parse a parsed IDL structure back into an IDL file
sub Parse($$)
{
	my($idl) = shift;
	my($filename) = shift;

	open(OUT, ">$filename") || die "can't open $filename";    

	pidl "/* parser auto-generated by pidl */\n\n";
	pidl "#ifdef HAVE_CONFIG_H\n";
	pidl "#include \"config.h\"\n";
        pidl "#endif\n\n";

        pidl "#include \"packet-dcerpc.h\"\n";
        pidl "#include \"packet-dcerpc-nt.h\"\n\n";
        pidl "#include \"packet-dcerpc-common.h\"\n\n";

	pidl "#define NDR_SCALARS 1\n";
	pidl "#define NDR_BUFFERS 2\n\n";

	pidl "extern const value_string NT_errors[];\n\n";

	foreach my $x (@{$idl}) {
	    $module = $x->{NAME}, if $x->{TYPE} eq "INTERFACE";
	}

	pidl "static int proto_dcerpc_$module = -1;\n\n";

	pidl "static gint ett_dcerpc_$module = -1;\n\n";

	pidl "static int hf_opnum = -1;\n";
	pidl "static int hf_rc = -1;\n";
	pidl "static int hf_ptr = -1;\n";
	pidl "static int hf_switch = -1;\n";
	pidl "static int hf_policy_handle = -1;\n";
	pidl "static int hf_array_size = -1;\n";
	pidl "static int hf_length_is = -1;\n";

	foreach my $x (@{$idl}) {
	    ($x->{TYPE} eq "MODULEHEADER") && 
		ModuleHeader($x);

	    if ($x->{TYPE} eq "INTERFACE") { 
		BuildNeeded($x);

		foreach my $y (keys(%needed)) {
		    pidl "static int $y = -1;\n", if $y =~ /^hf_/;
		}

		ParseInterface($x);
	    }
	}

	pidl "static e_uuid_t uuid_dcerpc_$module = {\n";
	pidl "\t0x" . substr($if_uuid, 0, 8);
	pidl ", 0x" . substr($if_uuid, 9, 4);
	pidl ", 0x" . substr($if_uuid, 14, 4) . ",\n";
	pidl "\t{ 0x" . substr($if_uuid, 19, 2);
	pidl ", 0x" . substr($if_uuid, 21, 2);
	pidl ", 0x" . substr($if_uuid, 24, 2);
	pidl ", 0x" . substr($if_uuid, 26, 2);
	pidl ", 0x" . substr($if_uuid, 28, 2);
	pidl ", 0x" . substr($if_uuid, 30, 2);
	pidl ", 0x" . substr($if_uuid, 32, 2);
	pidl ", 0x" . substr($if_uuid, 34, 2) . " }\n";
	pidl "};\n\n";

	pidl "static guint16 ver_dcerpc_$module = " . $if_version . ";\n\n";


	pidl "void proto_register_dcerpc_samr(void)\n";
	pidl "{\n";
        pidl "\tstatic hf_register_info hf[] = {\n";

	pidl "\t{ &hf_opnum, { \"Operation\", \"$module.opnum\", FT_UINT16, BASE_DEC, NULL, 0x0, \"Operation\", HFILL }},\n";
	pidl "\t{ &hf_policy_handle, { \"Policy handle\", \"$module.policy\", FT_BYTES, BASE_NONE, NULL, 0x0, \"Policy handle\", HFILL }},\n";
	pidl "\t{ &hf_rc, { \"Return code\", \"$module.rc\", FT_UINT32, BASE_HEX, VALS(NT_errors), 0x0, \"Return status code\", HFILL }},\n";
	pidl "\t{ &hf_switch, { \"Switch\", \"$module.switch\", FT_UINT16, BASE_DEC, NULL, 0x0, \"Switch\", HFILL }},\n";
	pidl "\t{ &hf_array_size, { \"Array size\", \"$module.array_size\", FT_UINT32, BASE_DEC, NULL, 0x0, \"Array size\", HFILL }},\n";
	pidl "\t{ &hf_length_is, { \"Length is\", \"$module.length_is\", FT_UINT32, BASE_DEC, NULL, 0x0, \"Length is\", HFILL }},\n";
	pidl "\t{ &hf_ptr, { \"Pointer\", \"$module.ptr\", FT_UINT32, BASE_HEX, NULL, 0x0, \"Pointer\", HFILL }},\n";

	foreach my $x (keys(%needed)) {
	    next, if !($x =~ /^hf_/);

	    pidl "\t{ &$x,\n";
	    pidl "\t  { \"$needed{$x}{name}\", \"$x\", $needed{$x}{ft}, $needed{$x}{base},\n";
	    pidl"\t  NULL, 0, \"$x\", HFILL }},\n";
	}

	pidl "\t};\n\n";

        pidl "\tstatic gint *ett[] = {\n";
	pidl "\t\t&ett_dcerpc_$module,\n";
	pidl "\t};\n\n";

        pidl "\tproto_dcerpc_$module = proto_register_protocol(\"$module\", \"$module\", \"$module\");\n\n";

	pidl "\tproto_register_field_array(proto_dcerpc_$module, hf, array_length (hf));\n";
        pidl "\tproto_register_subtree_array(ett, array_length(ett));\n";

        pidl "}\n\n";

	pidl "void proto_reg_handoff_dcerpc_$module(void)\n";
	pidl "{\n";
        pidl "\tdcerpc_init_uuid(proto_dcerpc_$module, ett_dcerpc_$module, \n";
	pidl "\t\t&uuid_dcerpc_$module, ver_dcerpc_$module, \n";
	pidl "\t\tdcerpc_dissectors, hf_opnum);\n";
        pidl "}\n";

	close(OUT);
}

1;
