###################################################
# Ethereal parser generator for IDL structures
# Copyright tpot@samba.org 2001
# Copyright tridge@samba.org 2000
# released under the GNU GPL

package IdlEParser;

use Data::Dumper;

my($res);

sub is_scalar_type($)
{
    my($type) = shift;

    return 1, if ($type eq "uint32");
    return 1, if ($type eq "long");
    return 1, if ($type eq "short");
    return 1, if ($type eq "char");
    return 1, if ($type eq "uint16");
    return 1, if ($type eq "hyper");

    return 0;
}

sub has_property($$)
{
    my($props) = shift;
    my($p) = shift;

    foreach my $d (@{$props}) {
	if (ref($d) ne "HASH") {
	    return 1, if ($d eq $p);
	    return 1, if ($d eq "in,out" && ($p eq "in" || $p eq "out"));
	} else {
	    foreach my $k (keys %{$d}) {
		$res .= "[$k($d->{$k})] ";
	    }
	}
    }

    return 0;
}

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
# parse a structure element
sub ParseElement($$)
{
    my($elt) = shift;
    my($flags) = shift;

#    (defined $elt->{PROPERTIES}) && ParseProperties($elt->{PROPERTIES});
#    ParseType($elt->{TYPE});

#    $res .= "/* ";
#    if ($elt->{POINTERS}) {
#	for (my($i)=0; $i < $elt->{POINTERS}; $i++) {
#	    $res .= "*";
#	}
#    }
#    $res .= "$elt->{NAME}";
#    (defined $elt->{ARRAY_LEN}) && ($res .= "[$elt->{ARRAY_LEN}]");

#    $res .= "*/\n\n";

    # Arg is a policy handle
	    
    if (has_property($elt->{PROPERTIES}, "context_handle")) {
	$res .= "\toffset = prs_policy_hnd(tvb, offset, pinfo, tree);\n";
	return;
    }

    # Parse type

    if ($flags =~ /scalars/) {

	# Pointers are scalars

	if ($elt->{POINTERS}) {
	    $res .= "\t\tptr_$elt->{NAME} = prs_ptr(tvb, offset, pinfo, tree, \"$elt->{NAME}\");\n";
	} else {

	    # Simple type are scalars too

	    if (is_scalar_type($elt->{TYPE})) {
		$res .= "\t\tprs_$elt->{TYPE}(tvb, offset, pinfo, tree, \"$elt->{NAME}}\");\n\n";
	    }
	}

    } else {

	# Scalars are not buffers, except if they are pointed to

	if (!is_scalar_type($elt->{TYPE}) || $elt->{POINTERS}) {

	    # If we have a pointer, check it

	    if ($elt->{POINTERS}) {
		$res .= "\t\tif (ptr_$elt->{NAME}) {\n\t";
	    }
	    
	    $res .= "\t\tprs_$elt->{TYPE}(tvb, offset, pinfo, tree, flags, \"$elt->{NAME}\");\n\n";
	    
	    if ($elt->{POINTERS}) {
		$res .= "\t\t}\n\n";
	    }
	}
    }

    return;
    
#    if (is_simple_type($elt->{TYPE})) {
#	if ($flags =~ /scalars/ && !$elt->{POINTERS}) {
#	    $res .= "\t\tprs_$elt->{TYPE}(tvb, offset, pinfo, tree, \"$elt->{NAME}}\");\n\n",
#	}
#    } else {
#	if ($flags =~ /buffers/) {
#	    if ($elt->{POINTERS}) {
#		$res .= "\t\tif (ptr_$elt->{NAME}) {\n\t";
#	    }
#	    $res .= "\t\tprs_$elt->{TYPE}(tvb, offset, pinfo, tree, flags, \"$elt->{NAME}\");\n\n";
#	    if ($elt->{POINTERS}) {
#		$res .= "\t\t}\n\n";
#	    }
#	}
#    }
}

#####################################################################
# parse a struct
sub ParseStruct($)
{
    my($struct) = shift;

    if (defined $struct->{ELEMENTS}) {

	# Parse scalars

	$res .= "\tif (flags & PARSE_SCALARS) {\n";

	foreach my $e (@{$struct->{ELEMENTS}}) {
	    ParseElement($e, "scalars");

#	    if (defined $e->{POINTERS}) {
#		$res .= "\t\toffset = prs_ptr(tvb, offset, pinfo, tree, &ptr_$e->{NAME}, \"$e->{NAME}\");\n";
#	    } else {
#		$res .= "\t\toffset = prs_$e->{TYPE}(tvb, offset, pinfo, tree, \"$e->{NAME}\");\n";
#	    }
	}	

	$res .= "\t}\n\n";

	# Parse buffers

	$res .= "\tif (flags & PARSE_BUFFERS) {\n";

	foreach my $e (@{$struct->{ELEMENTS}}) {
	    ParseElement($e, "buffers");
#	    $res .= "\t\tif (ptr_$e->{NAME})\n\t\t\toffset = prs_$e->{TYPE}(tvb, offset, pinfo, tree, \"$e->{NAME}\");\n\n",
#	    if (defined $e->{POINTERS});
	}

	$res .= "\t}\n\n";
    }
}


#####################################################################
# parse a union element
sub ParseUnionElement($)
{
    my($element) = shift;
    
#    $res .= "int prs_$element->{DATA}->{TYPE}()\n{\n";

#    $res .= "}\n\n";

    $res .= "\tcase $element->{DATA}->{NAME}: \n";
    $res .= "\t\toffset = prs_$element->{DATA}->{TYPE}(tvb, offset, pinfo, tree, \"$element->{DATA}->{NAME}\");\n\t\tbreak;\n";

#    $res .= "[case($element->{CASE})] ";
#    ParseElement($element->{DATA});
#    $res .= ";\n";
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

    $res .= "static int prs_$typedef->{NAME}(tvbuff_t *tvb, int offset,\
\tpacket_info *pinfo, proto_tree *tree)\n{\n";
    ParseType($typedef->{DATA});
    $res .= "}\n\n";
}

#####################################################################
# parse a function
sub ParseFunctionArg($$)
{ 
    my($arg) = shift;
    my($io) = shift;		# "in" or "out"

    if (has_property($arg->{PROPERTIES}, $io)) {
	ParseElement($arg, "scalars|buffers");
    }
}
    
#####################################################################
# parse a function
sub ParseFunction($)
{ 
    my($function) = shift;

    # Input function

    $res .= "static int $function->{NAME}_q(tvbuff_t *tvb, int offset,\
\tpacket_info *pinfo, proto_tree *tree, char *drep)\n{\n";

    foreach my $arg (@{$function->{DATA}}) {
	ParseFunctionArg($arg, "in");
    }
    
    $res .= "\n\treturn 0;\n}\n\n";
    
    # Output function

    $res .= "static int $function->{NAME}_r(tvbuff_t *tvb, int offset,\
\tpacket_info *pinfo, proto_tree *tree, char *drep)\n{\n";

    foreach my $arg (@{$function->{DATA}}) {
	ParseFunctionArg($arg, "out");
    }

    $res .= "\n\toffset = prs_ntstatus(tvb, offset, pinfo, tree);\n";

    $res .= "\n\treturn 0;\n}\n\n";

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
