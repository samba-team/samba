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
	die "arrays not done";
}


#####################################################################
# parse scalars in a structure element
sub ParseElementPushScalars($$)
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
sub ParseElementPushBuffers($$)
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
sub ParseStructPush($)
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
		ParseElementPushScalars($e, "r->");
	}	

	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPushBuffers($e, "r->");
	}

	if (defined $struct_len) {
		$res .= "\tndr_push_save(ndr, &len_save3);\n";
		$res .= "\tndr_push_restore(ndr, &len_save2);\n";
		$struct_len->{VALUE} = "len_save3.offset - len_save1.offset";
		ParseElementPushScalars($struct_len, "r->");
		$res .= "\tndr_push_restore(ndr, &len_save3);\n";
	}
}


#####################################################################
# parse a union element
sub ParseUnionElementPush($)
{
	die "unions not done";
}

#####################################################################
# parse a union
sub ParseUnionPush($)
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
    } else {
	$res .= "$data";
    }
}

#####################################################################
# parse a typedef
sub ParseTypedefPush($)
{
    my($typedef) = shift;

    $res .= "static NTSTATUS ndr_push_$typedef->{NAME}(struct ndr_push *ndr, struct $typedef->{NAME} *r)";
    $res .= "\n{\n";
    ParseTypePush($typedef->{DATA});
    $res .= "\treturn NT_STATUS_OK;\n";
    $res .= "}\n\n";
}

#####################################################################
# parse a function
sub ParseFunctionPushArg($$)
{ 
	my($arg) = shift;
	my($io) = shift;		# "in" or "out"

	if (!util::has_property($arg->{PROPERTIES}, $io)) {
		return;
	}

	ParseElementPushScalars($arg, "r->in.");
	ParseElementPushBuffers($arg, "r->in.");
}
    
#####################################################################
# parse a function
sub ParseFunctionPush($)
{ 
    my($function) = shift;

    # Input function
    $res .= "NTSTATUS ndr_push_$function->{NAME}(struct ndr_push *ndr, struct $function->{NAME} *r)\n{\n";

    foreach my $arg (@{$function->{DATA}}) {
	ParseFunctionPushArg($arg, "in");
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
	    ParseTypedefPush($d);
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
