###################################################
# Samba4 parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# released under the GNU GPL

package IdlParser;

use Data::Dumper;

my($res);

# the list of needed functions
my %needed;

#####################################################################
# parse a properties list
sub ParseProperties($)
{
    my($props) = shift;
    foreach my $d (@{$props}) {
	if (ref($d) ne "HASH") {
	    $res .= "[$d] ";
	} else {
	    foreach my $k (keys %{$d}) {
		$res .= "[$k($d->{$k})] ";
	    }
	}
    }
}

####################################################################
# work out the name of a size_is() variable
sub find_size_var($$)
{
	my($e) = shift;
	my($size) = shift;
	my($fn) = $e->{PARENT};

	if (util::is_constant($size)) {
		return $size;
	}
	
	if ($fn->{TYPE} ne "FUNCTION") {
		return "r->$size";
	}

	for my $e2 (@{$fn->{DATA}}) {
		if ($e2->{NAME} eq $size) {
			if (util::has_property($e2, "in")) {
				return "r->in.$size";
			}
			if (util::has_property($e2, "out")) {
				return "r->out.$size";
			}
		}
	}
	die "invalid variable in $size for element $e->{NAME} in $fn->{NAME}\n";
}


#####################################################################
# work out the correct alignment for a structure
sub struct_alignment($)
{
	my $s = shift;
	# why do we need a minimum alignment of 4 ?? 
	my $align = 4;
	for my $e (@{$s->{ELEMENTS}}) {
		if ($align < util::type_align($e)) {
			$align = util::type_align($e);
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

	my $size = find_size_var($e, util::array_size($e));

	if (defined $e->{CONFORMANT_SIZE}) {
		# the conformant size has already been pushed
	} elsif (!util::is_constant($size)) {
		# we need to emit the array size
		$res .= "\t\tNDR_CHECK(ndr_push_uint32(ndr, $size));\n";
	}

	if (util::is_scalar_type($e->{TYPE})) {
		$res .= "\t\tNDR_CHECK(ndr_push_array_$e->{TYPE}(ndr, $var_prefix$e->{NAME}, $size));\n";
	} else {
		$res .= "\t\tNDR_CHECK(ndr_push_array(ndr, ndr_flags, $var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_push_flags_fn_t)ndr_push_$e->{TYPE}));\n";
	}
}

#####################################################################
# print an array
sub ParseArrayPrint($$)
{
	my $e = shift;
	my $var_prefix = shift;
	my $size = find_size_var($e, util::array_size($e));

	if (util::is_scalar_type($e->{TYPE})) {
		$res .= "\t\tndr_print_array_$e->{TYPE}(ndr, \"$e->{NAME}\", $var_prefix$e->{NAME}, $size);\n";
	} else {
		$res .= "\t\tndr_print_array(ndr, \"$e->{NAME}\", $var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_print_fn_t)ndr_print_$e->{TYPE});\n";
	}
}

#####################################################################
# parse an array - pull side
sub ParseArrayPull($$$)
{
	my $e = shift;
	my $var_prefix = shift;
	my $ndr_flags = shift;

	my $size = find_size_var($e, util::array_size($e));
	my $alloc_size = $size;

	# if this is a conformant array then we use that size to allocate, and make sure
	# we allocate enough to pull the elements
	if (defined $e->{CONFORMANT_SIZE}) {
		$alloc_size = $e->{CONFORMANT_SIZE};

		$res .= "\tif ($size > $alloc_size) {\n";
		$res .= "\t\treturn ndr_pull_error(ndr, NDR_ERR_CONFORMANT_SIZE, \"Bad conformant size %u should be %u\", $alloc_size, $size);\n";
		$res .= "\t}\n";
	} elsif (!util::is_constant($size)) {
		# non fixed arrays encode the size just before the array
		$res .= "\t{\n";
		$res .= "\t\tuint32 _array_size;\n";
		$res .= "\t\tNDR_CHECK(ndr_pull_uint32(ndr, &_array_size));\n";
		$res .= "\t\tif ($size > _array_size) {\n";
		$res .= "\t\t\treturn ndr_pull_error(ndr, NDR_ERR_ARRAY_SIZE, \"Bad array size %u should be %u\", _array_size, $size);\n";
		$res .= "\t\t}\n";
		$res .= "\t}\n";
	}

	if (util::need_alloc($e) && !util::is_constant($size)) {
		$res .= "\t\tNDR_ALLOC_N_SIZE(ndr, $var_prefix$e->{NAME}, $alloc_size, sizeof($var_prefix$e->{NAME}\[0]));\n";
	}

	if (util::has_property($e, "length_is")) {
		die "we don't handle varying arrays yet";
	}

	if (util::is_scalar_type($e->{TYPE})) {
		$res .= "\t\tNDR_CHECK(ndr_pull_array_$e->{TYPE}(ndr, $var_prefix$e->{NAME}, $size));\n";
	} else {
		$res .= "\t\tNDR_CHECK(ndr_pull_array(ndr, $ndr_flags, (void **)$var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_pull_flags_fn_t)ndr_pull_$e->{TYPE}));\n";
	}
}


#####################################################################
# parse scalars in a structure element
sub ParseElementPushScalar($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $cprefix = util::c_push_prefix($e);

	if (defined $e->{VALUE}) {
		$res .= "\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $e->{VALUE}));\n";
	} elsif (util::need_wire_pointer($e)) {
		$res .= "\tNDR_CHECK(ndr_push_ptr(ndr, $var_prefix$e->{NAME}));\n";
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPushSwitch($e, $var_prefix, $ndr_flags, $switch);
	} elsif (util::is_builtin_type($e->{TYPE})) {
		$res .= "\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $cprefix$var_prefix$e->{NAME}));\n";
	} else {
		$res .= "\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));\n";
	}
}

#####################################################################
# print scalars in a structure element
sub ParseElementPrintScalar($$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my $cprefix = util::c_push_prefix($e);

	if (defined $e->{VALUE}) {
		$res .= "\tndr_print_$e->{TYPE}(ndr, \"$e->{NAME}\", $e->{VALUE});\n";
	} elsif (util::has_direct_buffers($e)) {
		$res .= "\tndr_print_ptr(ndr, \"$e->{NAME}\", $var_prefix$e->{NAME});\n";
		$res .= "\tndr->depth++;\n";
		ParseElementPrintBuffer($e, "r->");
		$res .= "\tndr->depth--;\n";
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPrintSwitch($e, $var_prefix, $switch);
	} else {
		$res .= "\tndr_print_$e->{TYPE}(ndr, \"$e->{NAME}\", $cprefix$var_prefix$e->{NAME});\n";
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
	my $switch_var = find_size_var($e, $switch);

	my $cprefix = util::c_pull_prefix($e);

	$res .= "\t{ uint16 _level;\n";
	$res .= "\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $ndr_flags, &_level, $cprefix$var_prefix$e->{NAME}));\n";
	$res .= "\tif ((($ndr_flags) & NDR_SCALARS) && (_level != $switch_var)) return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value %u in $e->{NAME}\");\n";
	$res .= "\t}\n";
}

#####################################################################
# push switch element
sub ParseElementPushSwitch($$$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $switch = shift;
	my $switch_var = find_size_var($e, $switch);
	my $cprefix = util::c_push_prefix($e);

	$res .= "\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $ndr_flags, $switch_var, $cprefix$var_prefix$e->{NAME}));\n";
}

#####################################################################
# print scalars in a structure element 
sub ParseElementPrintSwitch($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my $switch = shift;
	my $switch_var = find_size_var($e, $switch);
	my $cprefix = util::c_push_prefix($e);

	$res .= "\tndr_print_$e->{TYPE}(ndr, \"$e->{NAME}\", $switch_var, $cprefix$var_prefix$e->{NAME});\n";
}


#####################################################################
# parse scalars in a structure element - pull size
sub ParseElementPullScalar($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $cprefix = util::c_pull_prefix($e);

	if (defined $e->{VALUE}) {
		$res .= "\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $e->{VALUE}));\n";
	} elsif (util::need_wire_pointer($e)) {
		$res .= "\tNDR_CHECK(ndr_pull_uint32(ndr, &_ptr_$e->{NAME}));\n";
		$res .= "\tif (_ptr_$e->{NAME}) {\n";
		$res .= "\t\tNDR_ALLOC(ndr, $var_prefix$e->{NAME});\n";
		$res .= "\t} else {\n";
		$res .= "\t\t$var_prefix$e->{NAME} = NULL;\n";
		$res .= "\t}\n";
	} elsif (util::need_alloc($e)) {
		# no scalar component
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPullSwitch($e, $var_prefix, $ndr_flags, $switch);
	} elsif (util::is_builtin_type($e->{TYPE})) {
		$res .= "\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $cprefix$var_prefix$e->{NAME}));\n";
	} else {
		$res .= "\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));\n";
	}
}

#####################################################################
# parse buffers in a structure element
sub ParseElementPushBuffer($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $cprefix = util::c_push_prefix($e);

	if (util::is_pure_scalar($e)) {
		return;
	}

	if (util::need_wire_pointer($e)) {
		$res .= "\tif ($var_prefix$e->{NAME}) {\n";
	}
	    
	if (util::array_size($e)) {
		ParseArrayPush($e, "r->", "NDR_SCALARS|NDR_BUFFERS");
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		if ($e->{POINTERS}) {
			ParseElementPushSwitch($e, $var_prefix, "NDR_BUFFERS|NDR_SCALARS", $switch);
		} else {
			ParseElementPushSwitch($e, $var_prefix, "NDR_BUFFERS", $switch);
		}
	} elsif (util::is_builtin_type($e->{TYPE})) {
		$res .= "\t\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $cprefix$var_prefix$e->{NAME}));\n";
	} elsif ($e->{POINTERS}) {
		$res .= "\t\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, NDR_SCALARS|NDR_BUFFERS, $cprefix$var_prefix$e->{NAME}));\n";
	} else {
		$res .= "\t\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));\n";
	}

	if (util::need_wire_pointer($e)) {
		$res .= "\t}\n";
	}	
}

#####################################################################
# print buffers in a structure element
sub ParseElementPrintBuffer($$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my $cprefix = util::c_push_prefix($e);

	if (util::is_pure_scalar($e)) {
		return;
	}

	if (util::need_wire_pointer($e)) {
		$res .= "\tif ($var_prefix$e->{NAME}) {\n";
	}
	    
	if (util::array_size($e)) {
		ParseArrayPrint($e, "r->");
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		ParseElementPrintSwitch($e, $var_prefix, $switch);
	} else {
		$res .= "\t\tndr_print_$e->{TYPE}(ndr, \"$e->{NAME}\", $cprefix$var_prefix$e->{NAME});\n";
	}

	if (util::need_wire_pointer($e)) {
		$res .= "\t}\n";
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

	if (util::is_pure_scalar($e)) {
		return;
	}

	if (util::need_wire_pointer($e)) {
		$res .= "\tif ($var_prefix$e->{NAME}) {\n";
	}
	    
	if (util::array_size($e)) {
		ParseArrayPull($e, "r->", "NDR_SCALARS|NDR_BUFFERS");
	} elsif (my $switch = util::has_property($e, "switch_is")) {
		if ($e->{POINTERS}) {
			ParseElementPullSwitch($e, $var_prefix, "NDR_SCALARS|NDR_BUFFERS", $switch);
		} else {
			ParseElementPullSwitch($e, $var_prefix, "NDR_BUFFERS", $switch);
		}
	} elsif (util::is_builtin_type($e->{TYPE})) {
		$res .= "\t\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $cprefix$var_prefix$e->{NAME}));\n";
	} elsif ($e->{POINTERS}) {
		$res .= "\t\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, NDR_SCALARS|NDR_BUFFERS, $cprefix$var_prefix$e->{NAME}));\n";
	} else {
		$res .= "\t\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));\n";
	}

	if (util::need_wire_pointer($e)) {
		$res .= "\t}\n";
	}	
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

	# see if the structure contains a conformant array. If it
	# does, then it must be the last element of the structure, and
	# we need to push the conformant length early, as it fits on
	# the wire before the structure (and even before the structure
	# alignment)
	my $e = $struct->{ELEMENTS}[-1];
	if (defined $e->{ARRAY_LEN} && $e->{ARRAY_LEN} eq "*") {
		my $size = find_size_var($e, util::array_size($e));
		$e->{CONFORMANT_SIZE} = $size;
		$conform_e = $e;
		$res .= "\tNDR_CHECK(ndr_push_uint32(ndr, $size));\n";
	}

	my $align = struct_alignment($struct);
	$res .= "\tNDR_CHECK(ndr_push_align(ndr, $align));\n";

	$res .= "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";

	foreach my $e (@{$struct->{ELEMENTS}}) {
		$e->{PARENT} = $struct;
		ParseElementPushScalar($e, "r->", "NDR_SCALARS");
	}	

	$res .= "buffers:\n";
	$res .= "\tif (!(ndr_flags & NDR_BUFFERS)) goto done;\n";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPushBuffer($e, "r->", "NDR_BUFFERS");
	}

	$res .= "done:\n";
}

#####################################################################
# generate a struct print function
sub ParseStructPrint($)
{
	my($struct) = shift;

	if (! defined $struct->{ELEMENTS}) {
		return;
	}

	$res .= "\tndr->depth++;\n";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPrintScalar($e, "r->");
	}
	$res .= "\tndr->depth--;\n";
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
		$res .= "\tuint32 _conformant_size;\n";
		$conform_e->{CONFORMANT_SIZE} = "_conformant_size";
	}

	# declare any internal pointers we need
	foreach my $e (@{$struct->{ELEMENTS}}) {
		$e->{PARENT} = $struct;
		if (util::need_wire_pointer($e)) {
			$res .= "\tuint32 _ptr_$e->{NAME};\n";
		}
	}


	if (defined $conform_e) {
		$res .= "\tNDR_CHECK(ndr_pull_uint32(ndr, &$conform_e->{CONFORMANT_SIZE}));\n";
	}

	my $align = struct_alignment($struct);
	$res .= "\tNDR_CHECK(ndr_pull_align(ndr, $align));\n";

	$res .= "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPullScalar($e, "r->", "NDR_SCALARS");
	}	

	$res .= "buffers:\n";
	$res .= "\tif (!(ndr_flags & NDR_BUFFERS)) goto done;\n";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPullBuffer($e, "r->", "NDR_BUFFERS");
	}

	$res .= "done:\n";
}


#####################################################################
# parse a union - push side
sub ParseUnionPush($)
{
	my $e = shift;
	$res .= "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";
	$res .= "\tNDR_CHECK(ndr_push_uint16(ndr, level));\n";
	$res .= "\tswitch (level) {\n";
	foreach my $el (@{$e->{DATA}}) {
		$res .= "\tcase $el->{CASE}:\n";
		ParseElementPushScalar($el->{DATA}, "r->", "NDR_SCALARS");		
		$res .= "\tbreak;\n\n";
	}
	$res .= "\tdefault:\n";
	$res .= "\t\treturn ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);\n";
	$res .= "\t}\n";
	$res .= "buffers:\n";
	$res .= "\tif (!(ndr_flags & NDR_BUFFERS)) goto done;\n";
	$res .= "\tswitch (level) {\n";
	foreach my $el (@{$e->{DATA}}) {
		$res .= "\tcase $el->{CASE}:\n";
		ParseElementPushBuffer($el->{DATA}, "r->", "ndr_flags");
		$res .= "\tbreak;\n\n";
	}
	$res .= "\tdefault:\n";
	$res .= "\t\treturn ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);\n";
	$res .= "\t}\n";
	$res .= "done:\n";
}

#####################################################################
# print a union
sub ParseUnionPrint($)
{
	my $e = shift;

	$res .= "\tswitch (level) {\n";
	foreach my $el (@{$e->{DATA}}) {
		$res .= "\tcase $el->{CASE}:\n";
		ParseElementPrintScalar($el->{DATA}, "r->");
		$res .= "\tbreak;\n\n";
	}
	$res .= "\tdefault:\n\t\tndr_print_bad_level(ndr, name, level);\n";
	$res .= "\t}\n";
}

#####################################################################
# parse a union - pull side
sub ParseUnionPull($)
{
	my $e = shift;

	$res .= "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";
	$res .= "\tNDR_CHECK(ndr_pull_uint16(ndr, level));\n";
	$res .= "\tswitch (*level) {\n";
	foreach my $el (@{$e->{DATA}}) {
		$res .= "\tcase $el->{CASE}: {\n";
		my $e2 = $el->{DATA};
		if ($e2->{POINTERS}) {
			$res .= "\t\tuint32 _ptr_$e2->{NAME};\n";
		}
		ParseElementPullScalar($el->{DATA}, "r->", "NDR_SCALARS");		
		$res .= "\tbreak; }\n\n";
	}
	$res .= "\tdefault:\n";
	$res .= "\t\treturn ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", *level);\n";
	$res .= "\t}\n";
	$res .= "buffers:\n";
	$res .= "\tif (!(ndr_flags & NDR_BUFFERS)) goto done;\n";
	$res .= "\tswitch (*level) {\n";
	foreach my $el (@{$e->{DATA}}) {
		$res .= "\tcase $el->{CASE}:\n";
		ParseElementPullBuffer($el->{DATA}, "r->", "NDR_BUFFERS");
		$res .= "\tbreak;\n\n";
	}
	$res .= "\tdefault:\n";
	$res .= "\t\treturn ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", *level);\n";
	$res .= "\t}\n";
	$res .= "done:\n";
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

	if (! $needed{"push_$e->{NAME}"}) {
#		print "push_$e->{NAME} not needed\n";
		return;
	}

	if ($e->{DATA}->{TYPE} eq "STRUCT") {
		$res .= "static NTSTATUS ndr_push_$e->{NAME}(struct ndr_push *ndr, int ndr_flags, struct $e->{NAME} *r)";
		$res .= "\n{\n";
		ParseTypePush($e->{DATA});
		$res .= "\treturn NT_STATUS_OK;\n";
		$res .= "}\n\n";
	}

	if ($e->{DATA}->{TYPE} eq "UNION") {
		$res .= "static NTSTATUS ndr_push_$e->{NAME}(struct ndr_push *ndr, int ndr_flags, uint16 level, union $e->{NAME} *r)";
		$res .= "\n{\n";
		ParseTypePush($e->{DATA});
		$res .= "\treturn NT_STATUS_OK;\n";
		$res .= "}\n\n";
	}
}


#####################################################################
# parse a typedef - pull side
sub ParseTypedefPull($)
{
	my($e) = shift;

	if (! $needed{"pull_$e->{NAME}"}) {
#		print "pull_$e->{NAME} not needed\n";
		return;
	}

	if ($e->{DATA}->{TYPE} eq "STRUCT") {
		$res .= "static NTSTATUS ndr_pull_$e->{NAME}(struct ndr_pull *ndr, int ndr_flags, struct $e->{NAME} *r)";
		$res .= "\n{\n";
		ParseTypePull($e->{DATA});
		$res .= "\treturn NT_STATUS_OK;\n";
		$res .= "}\n\n";
	}

	if ($e->{DATA}->{TYPE} eq "UNION") {
		$res .= "static NTSTATUS ndr_pull_$e->{NAME}(struct ndr_pull *ndr, int ndr_flags, uint16 *level, union $e->{NAME} *r)";
		$res .= "\n{\n";
		ParseTypePull($e->{DATA});
		$res .= "\treturn NT_STATUS_OK;\n";
		$res .= "}\n\n";
	}
}


#####################################################################
# parse a typedef - push side
sub ParseTypedefPrint($)
{
	my($e) = shift;

	if ($e->{DATA}->{TYPE} eq "STRUCT") {
		$res .= "void ndr_print_$e->{NAME}(struct ndr_print *ndr, const char *name, struct $e->{NAME} *r)";
		$res .= "\n{\n";
		$res .= "\tndr_print_struct(ndr, name, \"$e->{NAME}\");\n";
		ParseTypePrint($e->{DATA});
		$res .= "}\n\n";
	}

	if ($e->{DATA}->{TYPE} eq "UNION") {
		$res .= "void ndr_print_$e->{NAME}(struct ndr_print *ndr, const char *name, uint16 level, union $e->{NAME} *r)";
		$res .= "\n{\n";
		$res .= "\tndr_print_union(ndr, name, level, \"$e->{NAME}\");\n";
		ParseTypePrint($e->{DATA});
		$res .= "}\n\n";
	}
}


#####################################################################
# parse a function
sub ParseFunctionPush($)
{ 
	my($function) = shift;

	# Input function
	$res .= "NTSTATUS ndr_push_$function->{NAME}(struct ndr_push *ndr, struct $function->{NAME} *r)\n{\n";

	foreach my $e (@{$function->{DATA}}) {
		if (util::has_property($e, "in")) {
			$e->{PARENT} = $function;
			if (util::array_size($e)) {
				$res .= "\tif (r->in.$e->{NAME}) {\n";
				if (!util::is_scalar_type($e->{TYPE})) {
					$res .= "\t\tint ndr_flags = NDR_SCALARS|NDR_BUFFERS;\n";
				}
				ParseArrayPush($e, "r->in.", "ndr_flags");
				$res .= "\t}\n";
			} else {
				ParseElementPushScalar($e, "r->in.", "NDR_SCALARS|NDR_BUFFERS");
				ParseElementPushBuffer($e, "r->in.", "NDR_SCALARS|NDR_BUFFERS");
			}
		}
	}
    
	$res .= "\n\treturn NT_STATUS_OK;\n}\n\n";
}

#####################################################################
# parse a function
sub ParseFunctionPull($)
{ 
	my($fn) = shift;

	# pull function args
	$res .= "NTSTATUS ndr_pull_$fn->{NAME}(struct ndr_pull *ndr, struct $fn->{NAME} *r)\n{\n";

	# declare any internal pointers we need
	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "out")) {
			if (util::need_wire_pointer($e)) {
				$res .= "\tuint32 _ptr_$e->{NAME};\n";
			}
		}
	}

	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "out")) {
			$e->{PARENT} = $fn;
			if (util::array_size($e)) {
				$res .= "\tif (r->out.$e->{NAME}) {\n";
				if (!util::is_scalar_type($e->{TYPE})) {
					$res .= "\t\tint ndr_flags = NDR_SCALARS|NDR_BUFFERS;\n";
				}
				ParseArrayPull($e, "r->out.", "ndr_flags");
				$res .= "\t}\n";
			} else {
				ParseElementPullScalar($e, "r->out.", "NDR_SCALARS|NDR_BUFFERS");
				if ($e->{POINTERS}) {
					ParseElementPullBuffer($e, "r->out.", "NDR_SCALARS|NDR_BUFFERS");
				}
			}
		}
	}

	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		$res .= "\tNDR_CHECK(ndr_pull_$fn->{RETURN_TYPE}(ndr, &r->out.result));\n";
	}

    
	$res .= "\n\treturn NT_STATUS_OK;\n}\n\n";
}

#####################################################################
# parse the interface definitions
sub ParseInterface($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};
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
		($d->{TYPE} eq "TYPEDEF") &&
		    ParseTypedefPrint($d);
	}
}

sub NeededFunction($)
{
	my $fn = shift;
	$needed{"pull_$fn->{NAME}"} = 1;
	$needed{"push_$fn->{NAME}"} = 1;
	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "out")) {
			$needed{"pull_$e->{TYPE}"} = 1;
		}
		if (util::has_property($e, "in")) {
			$needed{"push_$e->{TYPE}"} = 1;
		}
	}
}

sub NeededTypedef($)
{
	my $t = shift;
	if ($t->{DATA}->{TYPE} eq "STRUCT") {
		for my $e (@{$t->{DATA}->{ELEMENTS}}) {
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
			if ($needed{"pull_$t->{NAME}"}) {
				$needed{"pull_$e->{DATA}->{TYPE}"} = 1;
			}
			if ($needed{"push_$t->{NAME}"}) {
				$needed{"push_$e->{DATA}->{TYPE}"} = 1;
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
sub Parse($)
{
	my($idl) = shift;
	$res = "/* parser auto-generated by pidl */\n\n";
	$res .= "#include \"includes.h\"\n\n";
	foreach my $x (@{$idl}) {
		if ($x->{TYPE} eq "INTERFACE") { 
			BuildNeeded($x);
			ParseInterface($x);
		}
	}
	return $res;
}

1;
