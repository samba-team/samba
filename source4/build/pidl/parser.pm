###################################################
# Ethereal parser generator for IDL structures
# Copyright tpot@samba.org 2001
# Copyright tridge@samba.org 2000
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

#####################################################################
# parse an array - called in buffers context
sub ParseArray($)
{
    my($elt) = shift;

    $res .= "\tfor (i = 0; i < count; i++) {\n";
    if (util::is_scalar_type($elt)) {
	$res .= "\t\toffset = prs_$elt->{TYPE}(tvb, offset, pinfo, tree, NULL, \"$elt->{NAME});\n";
	$res .= "\t}\n\n";
    } else {
	$res .= "\t\toffset = prs_$elt->{TYPE}(tvb, offset, pinfo, tree, \"PARSE_SCALARS\", \"$elt->{NAME}\");\n";
	$res .= "\t}\n\n";

	$res .= "\tfor (i = 0; i < count; i++) {\n";
	$res .= "\t\toffset = prs_$elt->{TYPE}(tvb, offset, pinfo, tree, \"PARSE_BUFFERS\", \"$elt->{NAME}\");\n";
	$res .= "\t}\n\n";
    }
}


#####################################################################
# parse scalars in a structure element
sub ParseElementScalars($$)
{
	my($elt) = shift;
	my($var_prefix) = shift;

	if (defined $elt->{VALUE}) {
		$res .= "\tNDR_CHECK(ndr_push_$elt->{TYPE}(ndr, $elt->{VALUE}));\n";
	} elsif ($elt->{POINTERS} && 
		 !util::has_property($elt->{PROPERTIES}, "ref")) {
		$res .= "\tNDR_CHECK(ndr_push_ptr(ndr, $var_prefix$elt->{NAME}));\n";
	} else {
		$res .= "\tNDR_CHECK(ndr_push_$elt->{TYPE}(ndr, $var_prefix$elt->{NAME}));\n";
	}
}

#####################################################################
# parse buffers in a structure element
sub ParseElementBuffers($$)
{
	my($elt) = shift;
	my($var_prefix) = shift;

	if (util::has_property($elt->{PROPERTIES}, "ref")) {
		return;
	}

	if (util::is_scalar_type($elt->{TYPE}) && !$elt->{POINTERS}) {
		return;
	}

	if ($elt->{POINTERS}) {
		$res .= "\tif ($var_prefix$elt->{NAME}) {\n\t";
	}
	    
	if (util::has_property($elt->{PROPERTIES}, "size_is")) {
		ParseArray($elt);
	} else {
		if (util::is_scalar_type($elt->{TYPE})) {
			$res .= "\tNDR_CHECK(ndr_push_$elt->{TYPE}(ndr, *$var_prefix$elt->{NAME}));\n";
		} else {
			$res .= "\tNDR_CHECK(ndr_push_$elt->{TYPE}(ndr, $var_prefix$elt->{NAME}));\n";
		}
	}

	if ($elt->{POINTERS}) {
		$res .= "\t}\n";
	}	
}

#####################################################################
# parse a struct
sub ParseStruct($)
{
	my($struct) = shift;
	my($struct_len);

	if (! defined $struct->{ELEMENTS}) {
		return;
	}

	# see if we have a structure length
	foreach my $e (@{$struct->{ELEMENTS}}) {
		if (util::has_property($e->{PROPERTIES}, "struct_len")) {
			$struct_len = $e;
			$e->{VALUE} = "0";
		}
	}	

	if (defined $struct_len) {
		$res .= "\tstruct ndr_push_save len_save1, len_save2, len_save3;\n";
		$res .= "\tndr_push_save(ndr, &len_save1);\n";
	}

	foreach my $e (@{$struct->{ELEMENTS}}) {
		if ($e == $struct_len) {
			$res .= "\tNDR_CHECK(ndr_push_align_$e->{TYPE}(ndr));\n";
			$res .= "\tndr_push_save(ndr, &len_save2);\n";
		}
		ParseElementScalars($e, "r->");
	}	

	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementBuffers($e, "r->");
	}

	if (defined $struct_len) {
		$res .= "\tndr_push_save(ndr, &len_save3);\n";
		$res .= "\tndr_push_restore(ndr, &len_save2);\n";
		$struct_len->{VALUE} = "len_save3.offset - len_save1.offset";
		ParseElementScalars($struct_len, "r->");
		$res .= "\tndr_push_restore(ndr, &len_save3);\n";
	}
}


#####################################################################
# parse a union element
sub ParseUnionElement($)
{
    my($element) = shift;
    
    $res .= "\tcase $element->{DATA}->{NAME}: \n";
    $res .= "\t\toffset = prs_$element->{DATA}->{TYPE}(tvb, offset, pinfo, tree, \"$element->{DATA}->{NAME}\");\n\t\tbreak;\n";

}

#####################################################################
# parse a union
sub ParseUnion($)
{
    my($union) = shift;

    $res .= "\tswitch (level) {\n";

    (defined $union->{PROPERTIES}) && ParseProperties($union->{PROPERTIES});
    foreach my $e (@{$union->{DATA}}) {
	ParseUnionElement($e);
    }
    
    $res .= "\t}\n";
}

#####################################################################
# parse a type
sub ParseType($)
{
    my($data) = shift;

    if (ref($data) eq "HASH") {
	($data->{TYPE} eq "STRUCT") &&
	    ParseStruct($data);
	($data->{TYPE} eq "UNION") &&
	    ParseUnion($data);
    } else {
	$res .= "$data";
    }
}

#####################################################################
# parse a typedef
sub ParseTypedef($)
{
    my($typedef) = shift;

    $res .= "static NTSTATUS ndr_push_$typedef->{NAME}(struct ndr_push *ndr, struct $typedef->{NAME} *r)";
    $res .= "\n{\n";
    ParseType($typedef->{DATA});
    $res .= "\treturn NT_STATUS_OK;\n";
    $res .= "}\n\n";
}

#####################################################################
# parse a function
sub ParseFunctionArg($$)
{ 
	my($arg) = shift;
	my($io) = shift;		# "in" or "out"

	if (!util::has_property($arg->{PROPERTIES}, $io)) {
		return;
	}

	ParseElementScalars($arg, "r->in.");
	ParseElementBuffers($arg, "r->in.");
}
    
#####################################################################
# parse a function
sub ParseFunctionPush($)
{ 
    my($function) = shift;

    # Input function
    $res .= "NTSTATUS ndr_push_$function->{NAME}(struct ndr_push *ndr, struct $function->{NAME} *r)\n{\n";

    foreach my $arg (@{$function->{DATA}}) {
	ParseFunctionArg($arg, "in");
    }
    
    $res .= "\n\treturn NT_STATUS_OK;\n}\n\n";
}

#####################################################################
# parse a function
sub ParseFunctionPull($)
{ 
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
    foreach my $x (@{$idl}) {
	($x->{TYPE} eq "INTERFACE") && 
	    ParseInterface($x);
    }
    return $res;
}

1;
