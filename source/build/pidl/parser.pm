###################################################
# Samba4 parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# released under the GNU GPL

package IdlParser;

use Data::Dumper;

my($res);

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
sub find_size_var($)
{
	my($e) = shift;
	my($fn) = $e->{PARENT};
	my($size) = util::has_property($e, "size_is");
	
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
	die "invalid variable in size_is($size) for element $e->{NAME} in $fn->{NAME}\n";
}


#####################################################################
# parse an array - push side
sub ParseArrayPush($$)
{
	my $e = shift;
	my $var_prefix = shift;
	my $size = find_size_var($e);

	if (util::is_scalar_type($e->{TYPE})) {
		$res .= "\t\tNDR_CHECK(ndr_push_array_$e->{TYPE}(ndr, $var_prefix$e->{NAME}, $size));\n";
	} else {
		$res .= "\t\tNDR_CHECK(ndr_push_array(ndr, ndr_flags, $var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_push_flags_fn_t)ndr_push_$e->{TYPE}));\n";
	}
}

#####################################################################
# parse an array - pull side
sub ParseArrayPull($$)
{
	my $e = shift;
	my $var_prefix = shift;
	my $size = find_size_var($e);

	if (!util::has_property($e, "ref")) {
		$res .= "\t\tNDR_ALLOC_N_SIZE(ndr, $var_prefix$e->{NAME}, $size, sizeof($var_prefix$e->{NAME}\[0]));\n";
	}
	if (util::is_scalar_type($e->{TYPE})) {
		$res .= "\t\tNDR_CHECK(ndr_pull_array_$e->{TYPE}(ndr, $var_prefix$e->{NAME}, $size));\n";
	} else {
		$res .= "\t\tNDR_CHECK(ndr_pull_array(ndr, ndr_flags, (void **)$var_prefix$e->{NAME}, sizeof($var_prefix$e->{NAME}\[0]), $size, (ndr_pull_flags_fn_t)ndr_pull_$e->{TYPE}));\n";
	}
}


#####################################################################
# parse scalars in a structure element
sub ParseElementPushScalar($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;

	if (defined $e->{VALUE}) {
		$res .= "\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $e->{VALUE}));\n";
	} elsif ($e->{POINTERS} && 
		 !util::has_property($e, "ref")) {
		$res .= "\tNDR_CHECK(ndr_push_ptr(ndr, $var_prefix$e->{NAME}));\n";
	} elsif (util::is_builtin_type($e->{TYPE})) {
		if (util::is_scalar_type($e->{TYPE}) &&
		    util::has_property($e, "ref")) {
			$res .= "\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, *$var_prefix$e->{NAME}));\n";
		} else {
			$res .= "\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $var_prefix$e->{NAME}));\n";
		}
	} else {
		if (util::is_scalar_type($e->{TYPE}) ||
		    $e->{POINTERS}) {
			$res .= "\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $ndr_flags, $var_prefix$e->{NAME}));\n";
		} else {
			$res .= "\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $ndr_flags, &$var_prefix$e->{NAME}));\n";
		}
	}
}

#####################################################################
# parse scalars in a structure element - pull size
sub ParseElementPullScalar($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;

	if (defined $e->{VALUE}) {
		$res .= "\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $e->{VALUE}));\n";
	} elsif ($e->{POINTERS} && 
		 !util::has_property($e, "ref")) {
		$res .= "\tNDR_CHECK(ndr_pull_uint32(ndr, &_ptr_$e->{NAME}));\n";
		$res .= "\tif (_ptr_$e->{NAME}) {\n";
		$res .= "\t\tNDR_ALLOC(ndr, $var_prefix$e->{NAME});\n";
		$res .= "\t} else {\n";
		$res .= "\t\t$var_prefix$e->{NAME} = NULL;\n";
		$res .= "\t}\n";
	} elsif (!util::is_scalar_type($e->{TYPE}) &&
		 util::has_property($e, "ref")) {
		if (util::is_builtin_type($e->{TYPE})) {
			$res .= "\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $var_prefix$e->{NAME}));\n";
		} else {
			$res .= "\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $ndr_flags, $var_prefix$e->{NAME}));\n";
		}
	} else {
		if (util::is_builtin_type($e->{TYPE})) {
			if (!util::has_property($e, "ref")) {
				$res .= "\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, &$var_prefix$e->{NAME}));\n";
			} else {
				$res .= "\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $var_prefix$e->{NAME}));\n";
			}
		} else {
			$res .= "\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $ndr_flags, &$var_prefix$e->{NAME}));\n";
		}
	}
}

#####################################################################
# parse buffers in a structure element
sub ParseElementPushBuffer($$)
{
	my($e) = shift;
	my($var_prefix) = shift;

	if (util::has_property($e, "ref")) {
		return;
	}

	if (util::is_scalar_type($e->{TYPE}) && !$e->{POINTERS}) {
		return;
	}

	if ($e->{POINTERS}) {
		$res .= "\tif ($var_prefix$e->{NAME}) {\n";
	}
	    
	if (util::has_property($e, "size_is")) {
		ParseArrayPush($e, "r->");
	} else {
		if (util::is_scalar_type($e->{TYPE})) {
			$res .= "\t\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, *$var_prefix$e->{NAME}));\n";
		} elsif (!$e->{POINTERS}) {
			$res .= "\t\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, ndr_flags, &$var_prefix$e->{NAME}));\n";
		} elsif (util::is_builtin_type($e->{TYPE})) {
			$res .= "\t\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, $var_prefix$e->{NAME}));\n";
		} else {
			$res .= "\t\tNDR_CHECK(ndr_push_$e->{TYPE}(ndr, ndr_flags, $var_prefix$e->{NAME}));\n";
		}
	}

	if ($e->{POINTERS}) {
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

	if (util::has_property($e, "ref")) {
		return;
	}

	if (util::is_scalar_type($e->{TYPE}) && !$e->{POINTERS}) {
		return;
	}

	if ($e->{POINTERS}) {
		$res .= "\tif ($var_prefix$e->{NAME}) {\n";
	}
	    
	if (util::has_property($e, "size_is")) {
		ParseArrayPull($e, "r->");
	} else {
		if (!$e->{POINTERS} ||
		    $e->{TYPE} =~ "unistr.*") {
			if (util::is_builtin_type($e->{TYPE})) {
				$res .= "\t\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, &$var_prefix$e->{NAME}));\n";
			} else {
				$res .= "\t\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $ndr_flags, &$var_prefix$e->{NAME}));\n";
			}
		} elsif (util::is_builtin_type($e->{TYPE})) {
			$res .= "\t\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $var_prefix$e->{NAME}));\n";
		} else {
			$res .= "\t\tNDR_CHECK(ndr_pull_$e->{TYPE}(ndr, $ndr_flags, $var_prefix$e->{NAME}));\n";
		}
	}

	if ($e->{POINTERS}) {
		$res .= "\t}\n";
	}	
}

#####################################################################
# parse a struct
sub ParseStructPush($)
{
	my($struct) = shift;
	my($struct_len);

	if (! defined $struct->{ELEMENTS}) {
		return;
	}

	# see if we have a structure length
	foreach my $e (@{$struct->{ELEMENTS}}) {
		$e->{PARENT} = $struct;
		if (util::has_property($e, "struct_len")) {
			$struct_len = $e;
			$e->{VALUE} = "0";
		}
	}	

	if (defined $struct_len) {
		$res .= "\tstruct ndr_push_save _save1, _save2, _save3;\n";
		$res .= "\tndr_push_save(ndr, &_save1);\n";
	}

	$res .= "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";

	foreach my $e (@{$struct->{ELEMENTS}}) {
		if (defined($struct_len) && $e == $struct_len) {
			$res .= "\tNDR_CHECK(ndr_push_align_$e->{TYPE}(ndr));\n";
			$res .= "\tndr_push_save(ndr, &_save2);\n";
		}
		ParseElementPushScalar($e, "r->", "NDR_SCALARS");
	}	

	$res .= "buffers:\n";
	$res .= "\tif (!(ndr_flags & NDR_BUFFERS)) goto done;\n";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPushBuffer($e, "r->");
	}

	if (defined $struct_len) {
		$res .= "\tndr_push_save(ndr, &_save3);\n";
		$res .= "\tndr_push_restore(ndr, &_save2);\n";
		$struct_len->{VALUE} = "_save3.offset - _save1.offset";
		ParseElementPushScalar($struct_len, "r->", "NDR_SCALARS");
		$res .= "\tndr_push_restore(ndr, &_save3);\n";
	}

	$res .= "done:\n";
}

#####################################################################
# parse a struct - pull side
sub ParseStructPull($)
{
	my($struct) = shift;
	my($struct_len);

	if (! defined $struct->{ELEMENTS}) {
		return;
	}

	# declare any internal pointers we need
	foreach my $e (@{$struct->{ELEMENTS}}) {
		$e->{PARENT} = $struct;
		if ($e->{POINTERS} && 
		    !util::has_property($e, "ref")) {
			$res .= "\tuint32 _ptr_$e->{NAME};\n";
		}
	}


	# see if we have a structure length. If we do then we need to advance
	# the ndr_pull offset to that length past the front of the structure
	# when we have finished with the structure
	# we also need to make sure that we limit the size of our parsing
	# of this structure to the given size
	foreach my $e (@{$struct->{ELEMENTS}}) {
		if (util::has_property($e, "struct_len")) {
			$struct_len = $e;
			$e->{VALUE} = "&_size";
		}
	}	

	if (defined $struct_len) {
		$res .= "\tuint32 _size;\n";
		$res .= "\tstruct ndr_pull_save _save;\n";
		$res .= "\tndr_pull_save(ndr, &_save);\n";
	}

	$res .= "\tif (!(ndr_flags & NDR_SCALARS)) goto buffers;\n";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPullScalar($e, "r->", "NDR_SCALARS");
		if (defined($struct_len) && $e == $struct_len) {
			$res .= "\tNDR_CHECK(ndr_pull_limit_size(ndr, _size, 4));\n";
		}
	}	

	$res .= "buffers:\n";
	$res .= "\tif (!(ndr_flags & NDR_BUFFERS)) goto done;\n";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPullBuffer($e, "r->", "ndr_flags");
	}

	if (defined $struct_len) {
		$res .= "\tndr_pull_restore(ndr, &_save);\n";
		$res .= "\tNDR_CHECK(ndr_pull_advance(ndr, _size));\n";
	}

	$res .= "done:\n";
}


#####################################################################
# parse a union element
sub ParseUnionElementPush($)
{
	die "unions not done";
}

#####################################################################
# parse a union - push side
sub ParseUnionPush($)
{
	die "unions not done";	
}

#####################################################################
# parse a union - pull side
sub ParseUnionPull($)
{
	die "unions not done";	
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
# parse a typedef - push side
sub ParseTypedefPush($)
{
	my($e) = shift;

	$res .= "static NTSTATUS ndr_push_$e->{NAME}(struct ndr_push *ndr, int ndr_flags, struct $e->{NAME} *r)";
	$res .= "\n{\n";
	ParseTypePush($e->{DATA});
	$res .= "\treturn NT_STATUS_OK;\n";
	$res .= "}\n\n";
}


#####################################################################
# parse a typedef - pull side
sub ParseTypedefPull($)
{
	my($e) = shift;

	$res .= "static NTSTATUS ndr_pull_$e->{NAME}(struct ndr_pull *ndr, int ndr_flags, struct $e->{NAME} *r)";
	$res .= "\n{\n";
	ParseTypePull($e->{DATA});
	$res .= "\treturn NT_STATUS_OK;\n";
	$res .= "}\n\n";
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
			if (util::has_property($e, "size_is")) {
				$res .= "\tif (r->in.$e->{NAME}) {\n";
				if (!util::is_scalar_type($e->{TYPE})) {
					$res .= "\t\tint ndr_flags = NDR_SCALARS|NDR_BUFFERS;\n";
				}
				ParseArrayPush($e, "r->in.");
				$res .= "\t}\n";
			} else {
				ParseElementPushScalar($e, "r->in.", "NDR_SCALARS|NDR_BUFFERS");
				ParseElementPushBuffer($e, "r->in.");
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
		if (util::has_property($e, "out") &&
		    $e->{POINTERS} && 
		    !util::is_scalar_type($e->{TYPE}) &&
		    !util::has_property($e, "ref")) {
			$res .= "\tuint32 _ptr_$e->{NAME};\n";
		}
	}

	foreach my $e (@{$fn->{DATA}}) {
		if (util::has_property($e, "out")) {
			$e->{PARENT} = $fn;
			if (util::has_property($e, "size_is")) {
				$res .= "\tif (r->out.$e->{NAME}) {\n";
				if (!util::is_scalar_type($e->{TYPE})) {
					$res .= "\t\tint ndr_flags = NDR_SCALARS|NDR_BUFFERS;\n";
				}
				ParseArrayPull($e, "r->out.");
				$res .= "\t}\n";
			} else {
				if ($e->{POINTERS} &&
				    !util::has_property($e, "ref")) {
					$res .= "\tNDR_ALLOC(ndr, r->out.$e->{NAME});\n";
				}
				ParseElementPullScalar($e, "r->out.", "NDR_SCALARS|NDR_BUFFERS");
				ParseElementPullBuffer($e, "r->out.", "NDR_SCALARS|NDR_BUFFERS");
			}
		}
	}

	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		$res .= "\tNDR_CHECK(ndr_pull_$fn->{RETURN_TYPE}(ndr, &r->out.result));\n";
	}

    
	$res .= "\n\treturn NT_STATUS_OK;\n}\n\n";
}

#####################################################################
# parse a typedef
sub ParseTypedef($)
{
	my($e) = shift;
	ParseTypedefPush($e);
	ParseTypedefPull($e);
}

#####################################################################
# parse a function
sub ParseFunction($)
{
	my $i = shift;
	ParseFunctionPush($i);
	ParseFunctionPull($i);
}

#####################################################################
# parse the interface definitions
sub ParseInterface($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};
	foreach my $d (@{$data}) {
		($d->{TYPE} eq "TYPEDEF") &&
		    ParseTypedef($d);
		($d->{TYPE} eq "FUNCTION") && 
		    ParseFunction($d);
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
		($x->{TYPE} eq "INTERFACE") && 
		    ParseInterface($x);
	}
	return $res;
}

1;
