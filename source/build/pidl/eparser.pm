###################################################
# Samba4 parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001,2004
# released under the GNU GPL

package IdlEParser;

use strict;

# the list of needed functions
my %needed;
my %structs;

my $module;
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
		pidl "\t{ guint32 _flags_save_$e->{TYPE} = ndr->flags;\n";
		pidl "\tndr->flags |= $flags;\n";
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
		pidl "\t\treturn; // ndr_pull_error(ndr, NDR_ERR_CONFORMANT_SIZE, \"Bad conformant size %u should be %u\", $alloc_size, $size);\n";
		pidl "\t}\n";
	} elsif (!util::is_inline_array($e)) {
		if ($var_prefix =~ /^r->out/ && $size =~ /^\*r->in/) {
			my $size2 = substr($size, 1);
			pidl "if (ndr->flags & LIBNDR_FLAG_REF_ALLOC) {	NDR_ALLOC(ndr, $size2); }\n";
		}

		# non fixed arrays encode the size just before the array
		pidl "\t{\n";
		pidl "\t\tuint32_t _array_size;\n";
		pidl "\t\tndr_pull_uint32(ndr, tree, hf_array_size, &_array_size);\n";
		if ($size =~ /r->in/) {
			pidl "\t\tif (!(ndr->flags & LIBNDR_FLAG_REF_ALLOC) && _array_size != $size) {\n";
		} else {
			pidl "\t\tif ($size != _array_size) {\n";
		}
		pidl "\t\t\t//return ndr_pull_error(ndr, NDR_ERR_ARRAY_SIZE, \"Bad array size %u should be %u\", _array_size, $size);\n";
		pidl "\t\t\treturn;\n";
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
		pidl "\t\tndr_pull_uint32(ndr, tree, hf_array_offset, &_offset);\n";
		pidl "\t\tndr_pull_uint32(ndr, tree, hf_array_length, &_length);\n";
		pidl "\t\tif (_offset != 0) return; // ndr_pull_error(ndr, NDR_ERR_OFFSET, \"Bad array offset 0x%08x\", _offset);\n";
		pidl "\t\tif (_length > $size || _length != $length) return; // ndr_pull_error(ndr, NDR_ERR_LENGTH, \"Bad array length 0x%08x > size 0x%08x\", _offset, $size);\n\n";
		$size = "_length";
	}

	if (util::is_scalar_type($e->{TYPE})) {
		pidl "\t\tndr_pull_array_$e->{TYPE}(ndr, $ndr_flags, tree, \"" . field2name($e->{NAME}) . "\", hf_$e->{NAME}_$e->{TYPE}, $var_prefix$e->{NAME}, $size);\n";
	} else {
		pidl "\t\tndr_pull_array(ndr, $ndr_flags, tree, \"" . field2name($e->{NAME}) . "\", (void **)$var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_pull_flags_fn_t)ndr_pull_$e->{TYPE});\n";
	}

	pidl "\t}\n";
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
		pidl "\t\tndr_pull_$e2->{TYPE}(ndr, tree, hf_level, &_level);\n";
		if ($switch_var =~ /r->in/) {
			pidl "\t\tif (!(ndr->flags & LIBNDR_FLAG_REF_ALLOC) && _level != $switch_var) {\n";
		} else {
			pidl "\t\tif (_level != $switch_var) {\n";
		}
		pidl "\t\t\treturn; // ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value %u in $e->{NAME}\", _level);\n";
		pidl "\t\t}\n";
		if ($switch_var =~ /r->/) {
			pidl "else { $switch_var = _level; }\n";
		}
		pidl "\t}\n";
	}

	my $sub_size = util::has_property($e, "subcontext");
	if (defined $sub_size) {
		pidl "\tndr_pull_subcontext_union_fn(ndr, $sub_size, $switch_var, $cprefix$var_prefix$e->{NAME}, (ndr_pull_union_fn_t) ndr_pull_$e->{TYPE});\n";
	} else {
		pidl "\tndr_pull_$e->{TYPE}(ndr, $ndr_flags, tree, $switch_var, $cprefix$var_prefix$e->{NAME});\n";
	}


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
		pidl "\tndr_pull_relative(ndr, tree, (const void **)&$var_prefix$e->{NAME}, sizeof(*$var_prefix$e->{NAME}), (ndr_pull_flags_fn_t)ndr_pull_$e->{TYPE});\n";
	} elsif (util::is_inline_array($e)) {
		ParseArrayPull($e, "r->", "NDR_SCALARS");
	} elsif (util::need_wire_pointer($e)) {
		pidl "\tndr_pull_ptr(ndr, tree, hf_ptr, &_ptr_$e->{NAME});\n";
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
			pidl "\tndr_pull_subcontext_fn(ndr, tree, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_fn_t) ndr_pull_$e->{TYPE});\n";
		} else {
			pidl "\tndr_pull_subcontext_flags_fn(ndr, tree, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_flags_fn_t) ndr_pull_$e->{TYPE});\n";
		}
	} elsif (util::is_builtin_type($e->{TYPE})) {
		pidl "\tndr_pull_$e->{TYPE}(ndr, tree, hf_$e->{NAME}_$e->{TYPE}, $cprefix$var_prefix$e->{NAME});\n";
	} else {
		pidl "\tndr_pull_$e->{TYPE}(ndr, $ndr_flags, get_subtree(tree, \"" . field2name($e->{NAME}) . "\", ndr, ett_$e->{TYPE}), $cprefix$var_prefix$e->{NAME});\n";
	}

	end_flags($e);
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
				pidl "\tndr_pull_subcontext_flags_fn(ndr, tree, $sub_size, $cprefix$var_prefix$e->{NAME}, (ndr_pull_flags_fn_t) ndr_pull_$e->{TYPE});\n";
			}
		}
	} elsif (util::is_builtin_type($e->{TYPE})) {
		pidl "\t\tndr_pull_$e->{TYPE}(ndr, tree, hf_$e->{NAME}_$e->{TYPE}, $cprefix$var_prefix$e->{NAME});\n";
	} elsif ($e->{POINTERS}) {
		pidl "\t\tndr_pull_$e->{TYPE}(ndr, NDR_SCALARS|NDR_BUFFERS, get_subtree(tree, \"" . field2name($e->{NAME}) . "\", ndr, ett_$e->{TYPE}), $cprefix$var_prefix$e->{NAME});\n";
	} else {
		pidl "\t\tndr_pull_$e->{TYPE}(ndr, $ndr_flags, get_subtree(tree, \"" . field2name($e->{NAME}) . "\", ndr, ett_$e->{TYPE}), $cprefix$var_prefix$e->{NAME});\n";
	}

	if (util::need_wire_pointer($e)) {
		pidl "\t}\n";
	}	

	end_flags($e);
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
		pidl "\tndr_pull_uint32(ndr, tree, hf_conformant_size, &$conform_e->{CONFORMANT_SIZE});\n";
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
		pidl "\t\treturn; // ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);\n";
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
		pidl "\t\treturn; // ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);\n";
	}
	pidl "\t}\n";
	pidl "\tndr_pull_struct_end(ndr);\n";
	pidl "done:\n";
	end_flags($e);
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
# parse a typedef - pull side
sub ParseTypedefPull($)
{
	my($e) = shift;
	my $static = fn_prefix($e);

	if (! $needed{"pull_$e->{NAME}"}) {
#		print "pull_$e->{NAME} not needed\n";
		return;
	}

	pidl "/*\n\n";
	pidl IdlDump::DumpTypedef($e);
	pidl "*/\n\n";

	if ($e->{DATA}->{TYPE} eq "STRUCT") {
		pidl $static . "void ndr_pull_$e->{NAME}(struct ndr_pull *ndr, int ndr_flags, proto_tree *tree, struct $e->{NAME} *r)";
		pidl "\n{\n";
		ParseTypePull($e->{DATA});
		pidl "\treturn;\n";
		pidl "}\n\n";
	}

	if ($e->{DATA}->{TYPE} eq "UNION") {
		pidl $static . "void ndr_pull_$e->{NAME}(struct ndr_pull *ndr, int ndr_flags, proto_tree *tree, uint16_t level, union $e->{NAME} *r)";
		pidl "\n{\n";
		ParseTypePull($e->{DATA});
		pidl "\treturn;\n";
		pidl "}\n\n";
	}
}

#####################################################################
# parse a function element
sub ParseFunctionElementPull($$)
{ 
	my $e = shift;
	my $inout = shift;

	if (util::array_size($e)) {
		if (util::need_wire_pointer($e)) {
			pidl "\tndr_pull_ptr(ndr, &_ptr_$e->{NAME});\n";
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

	pidl "/*\n\n";
	pidl IdlDump::DumpFunction($fn);
	pidl "*/\n\n";

	# request function
	pidl "int $fn->{NAME}_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)\n{\n";

	pidl "\tstruct ndr_pull *ndr = ndr_pull_init(tvb, offset, pinfo, drep);\n";
	pidl "\tstruct $fn->{NAME} *r = (struct $fn->{NAME} *)g_malloc(sizeof(struct $fn->{NAME}));\n\n";

	# declare any internal pointers we need
	foreach my $e (@{$fn->{DATA}}) {
		if (util::need_wire_pointer($e) &&
		    util::has_property($e, "in")) {
			pidl "\tuint32_t _ptr_$e->{NAME};\n";
		}
	}

	pidl "\n\tZERO_STRUCTP(r);\n\n";

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

	pidl "\n\treturn ndr->offset;\n";
	pidl "}\n\n";

	# response function
	pidl "int $fn->{NAME}_resp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)\n{\n";

	pidl "\tstruct ndr_pull *ndr = ndr_pull_init(tvb, offset, pinfo, drep);\n";
	pidl "\tstruct $fn->{NAME} *r = (struct $fn->{NAME} *)g_malloc(sizeof(struct $fn->{NAME}));\n\n";

	# declare any internal pointers we need
	foreach my $e (@{$fn->{DATA}}) {
		if (util::need_wire_pointer($e) &&
		    util::has_property($e, "out")) {
			pidl "\tuint32_t _ptr_$e->{NAME};\n";
		}
	}

	pidl "\tZERO_STRUCTP(r);\n\n";

	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "out")) {
			ParseFunctionElementPull($e, "out");
		}
	}

	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		pidl "\tndr_pull_$fn->{RETURN_TYPE}(ndr, tree, hf_rc, &r->out.result);\n";
	}

	pidl "\n\treturn ndr->offset;\n";
	pidl "}\n\n";
}

#####################################################################
# produce a function call table
sub FunctionTable($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};

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
		    ParseTypedefPull($d);
		($d->{TYPE} eq "FUNCTION") && 
		    ParseFunctionPull($d);
	}

	FunctionTable($interface);

}

sub type2ft($)
{
    my($t) = shift;
 
    return "FT_UINT32", if ($t eq "uint32");
    return "FT_UINT16", if ($t eq "uint16");
    return "FT_UINT8", if ($t eq "uint8");
    return "FT_BYTES";
}

sub type2base($)
{
    my($t) = shift;
 
    return "BASE_DEC", if ($t eq "uint32") or ($t eq "uint16") or
	($t eq "uint8");
    return "BASE_NONE";
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

sub NeededFunction($)
{
	my $fn = shift;
	$needed{"pull_$fn->{NAME}"} = 1;
	foreach my $e (@{$fn->{DATA}}) {
		$e->{PARENT} = $fn;
		$needed{"pull_$e->{TYPE}"} = 1;

		if (util::is_scalar_type($e->{TYPE})) {
		    $needed{"hf_$e->{NAME}_$e->{TYPE}"} = {
			'name' => field2name($e->{NAME}),
			'type' => $e->{TYPE},
			'ft'   => type2ft($e->{TYPE}),
			'base' => type2base($e->{TYPE})
			};
		    $e->{PARENT} = $fn;
		} else {
		    $needed{"ett_$e->{TYPE}"} = 1;
		}
	}
}

sub NeededTypedef($)
{
	my $t = shift;
	if (util::has_property($t->{DATA}, "public")) {
		$needed{"pull_$t->{NAME}"} = 1;
	}

	if ($t->{DATA}->{TYPE} eq "STRUCT") {

	    for my $e (@{$t->{DATA}->{ELEMENTS}}) {
		$e->{PARENT} = $t->{DATA};
		if ($needed{"pull_$t->{NAME}"}) {
		    $needed{"pull_$e->{TYPE}"} = 1;
		}
	    
		if (util::is_scalar_type($e->{TYPE})) {
		
		    $needed{"hf_$e->{NAME}_$e->{TYPE}"} = {
			'name' => field2name($e->{NAME}),
			'type' => $e->{TYPE},
			'ft'   => type2ft($e->{TYPE}),
			'base' => type2base($e->{TYPE})
			};
		    
		    $e->{PARENT} = $t->{DATA};
		    
		    if ($needed{"pull_$t->{NAME}"}) {
			$needed{"pull_$e->{TYPE}"} = 1;
		    }
		} else {
		    
		    $needed{"ett_$e->{TYPE}"} = 1;
		    
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
				$needed{"ett_$e->{DATA}{TYPE}"} = 1;
			}
		}

	    $needed{"ett_$t->{NAME}"} = 1;
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
# Generate a header file that contains function prototypes for 
# structs and typedefs.
sub ParseHeader($$)
{
	my($idl) = shift;
	my($filename) = shift;

	open(OUT, ">$filename") || die "can't open $filename";    

	pidl "/* parser auto-generated by pidl */\n\n";

	foreach my $x (@{$idl}) {
	    if ($x->{TYPE} eq "INTERFACE") { 
		foreach my $d (@{$x->{DATA}}) {

		    # Make prototypes for [public] structures and
		    # unions.

		    if ($d->{TYPE} eq "TYPEDEF" and 
			util::has_property($d->{DATA}, "public")) {
			
			if ($d->{DATA}{TYPE} eq "STRUCT") { 
			    pidl "void ndr_pull_$d->{NAME}(struct ndr_pull *ndr, int ndr_flags, proto_tree *tree, struct $d->{NAME} *r);\n\n";
			}

			if ($d->{DATA}{TYPE} eq "UNION") {
			    pidl "void ndr_pull_$d->{NAME}(struct ndr_pull *ndr, int ndr_flags, proto_tree *tree, struct $d->{NAME} *r, uint16 level);\n\n";
			}
		    }
		}
	    }
	}

	close(OUT);
}

#####################################################################
# parse a parsed IDL structure back into an IDL file
sub Parse($$)
{
	my($idl) = shift;
	my($filename) = shift;

	%needed = ();		# Clear after generating header file

	open(OUT, ">$filename") || die "can't open $filename";    

	# Look for name of module

	foreach my $x (@{$idl}) {

	    if ($x->{TYPE} eq "INTERFACE") { 
		ModuleHeader($x);
		$module = $x->{NAME};
		BuildNeeded($x);
	    }
	}
	
	pidl "/* parser auto-generated by pidl */\n\n";
	pidl "#include \"eparser.h\"\n\n";

	pidl "extern const value_string NT_errors[];\n\n";

	pidl "static int hf_opnum = -1;\n";
	pidl "static int hf_rc = -1;\n";
	pidl "static int hf_ptr = -1;\n";
	pidl "static int hf_array_size = -1;\n";
	pidl "static int hf_array_offset = -1;\n";
	pidl "static int hf_array_length = -1;\n";
	pidl "static int hf_level = -1;\n";
	pidl "static int hf_conformant_size = -1;\n";

	# Declarations for hf variables

	foreach my $y (keys(%needed)) {
	    pidl "static int $y = -1;\n", if $y =~ /^hf_/;
	}

	pidl "\n";

	# Declarations for ett variables

	foreach my $y (keys(%needed)) {
	    pidl "static gint $y = -1;\n", if $y =~ /^ett_/;
	}

	pidl "\n";

	foreach my $x (@{$idl}) {
		($x->{TYPE} eq "MODULEHEADER") && 
		    ModuleHeader($x);

		if ($x->{TYPE} eq "INTERFACE") { 
			BuildNeeded($x);
			ParseInterface($x);
		}
	}

	pidl "int proto_dcerpc_pidl_$module = -1;\n\n";

	pidl "static gint ett_dcerpc_$module = -1;\n\n";

	if (defined($if_uuid)) {

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
	}

	pidl "void proto_register_dcerpc_pidl_$module(void)\n";
	pidl "{\n";

	pidl "\tstatic hf_register_info hf[] = {\n";
	
	pidl "\t{ &hf_opnum, { \"Operation\", \"$module.opnum\", FT_UINT16, BASE_DEC, NULL, 0x0, \"Operation\", HFILL }},\n";
	pidl "\t{ &hf_rc, { \"Return code\", \"$module.rc\", FT_UINT32, BASE_HEX, VALS(NT_errors), 0x0, \"Return status code\", HFILL }},\n";
	pidl "\t{ &hf_array_size, { \"Array size\", \"$module.array_size\", FT_UINT32, BASE_DEC, NULL, 0x0, \"Array size\", HFILL }},\n";
	pidl "\t{ &hf_array_offset, { \"Array offset\", \"$module.array_offset\", FT_UINT32, BASE_DEC, NULL, 0x0, \"Array offset\", HFILL }},\n";
	pidl "\t{ &hf_array_length, { \"Array length\", \"$module.array_length\", FT_UINT32, BASE_DEC, NULL, 0x0, \"Array length\", HFILL }},\n";
	pidl "\t{ &hf_ptr, { \"Pointer\", \"$module.ptr\", FT_UINT32, BASE_HEX, NULL, 0x0, \"Pointer\", HFILL }},\n";
	pidl "\t{ &hf_level, { \"Level\", \"$module.level\", FT_UINT32, BASE_DEC, NULL, 0x0, \"Level\", HFILL }},\n";
	pidl "\t{ &hf_conformant_size, { \"Conformant size\", \"$module.conformant_size\", FT_UINT32, BASE_DEC, NULL, 0x0, \"Conformant size\", HFILL }},\n";

	foreach my $x (keys(%needed)) {
	    next, if !($x =~ /^hf_/);
	    pidl "\t{ &$x,\n";
	    pidl "\t  { \"$needed{$x}{name}\", \"$x\", $needed{$x}{ft}, $needed{$x}{base}, NULL, 0, \"$x\", HFILL }},\n";
	}
	
	pidl "\t};\n\n";

	pidl "\tstatic gint *ett[] = {\n";
	pidl "\t\t&ett_dcerpc_$module,\n";
	foreach my $x (keys(%needed)) {
	    pidl "\t\t&$x,\n", if $x =~ /^ett_/;
	}
	pidl "\t};\n\n";
	
	if (defined($if_uuid)) {

	    pidl "\tproto_dcerpc_pidl_$module = proto_register_protocol(\"pidl_$module\", \"pidl_$module\", \"pidl_$module\");\n\n";

	    pidl "\tproto_register_field_array(proto_dcerpc_pidl_$module, hf, array_length (hf));\n";
	    pidl "\tproto_register_subtree_array(ett, array_length(ett));\n";

	    pidl "}\n\n";

	    pidl "void proto_reg_handoff_dcerpc_pidl_$module(void)\n";
	    pidl "{\n";
	    pidl "\tdcerpc_init_uuid(proto_dcerpc_pidl_$module, ett_dcerpc_$module, \n";
	    pidl "\t\t&uuid_dcerpc_$module, ver_dcerpc_$module, \n";
	    pidl "\t\tdcerpc_dissectors, hf_opnum);\n";
	    pidl "}\n";

	} else {

	    pidl "\tint proto_dcerpc;\n\n";
	    pidl "\tproto_dcerpc = proto_get_id_by_filter_name(\"dcerpc\");\n";
	    pidl "\tproto_register_field_array(proto_dcerpc, hf, array_length(hf));\n";
	    pidl "\tproto_register_subtree_array(ett, array_length(ett));\n";

	    pidl "}\n";

	}

	close(OUT);
}

1;
