###################################################
# Ethereal parser generator for IDL structures
# Copyright tpot@samba.org 2001
# Copyright tridge@samba.org 2000
# released under the GNU GPL

package IdlEParser;

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
# parse a structure element
sub ParseElement($)
{
    my($element) = shift;
    (defined $element->{PROPERTIES}) && ParseProperties($element->{PROPERTIES});
    ParseType($element->{TYPE});
    $res .= " ";
    if ($element->{POINTERS}) {
	for (my($i)=0; $i < $element->{POINTERS}; $i++) {
	    $res .= "*";
	}
    }
    $res .= "$element->{NAME}";
    (defined $element->{ARRAY_LEN}) && ($res .= "[$element->{ARRAY_LEN}]");
}

#####################################################################
# parse a struct
sub ParseStruct($)
{
    my($struct) = shift;

    if (defined $struct->{ELEMENTS}) {

	# Parse scalars

	$res .= "\t/* Parse scalars */\n\n";

	foreach my $e (@{$struct->{ELEMENTS}}) {
	    if (defined $e->{POINTERS}) {
		$res .= "\toffset = dissect_ptr(tvb, offset, pinfo, tree, &ptr_$e->{NAME});\n";
	    } else {
		$res .= "\toffset = dissect_$e->{TYPE}(tvb, offset, pinfo, tree);\n";
	    }
	}	

	# Parse buffers

	$res .= "\n\t/* Parse buffers */\n\n";

	foreach my $e (@{$struct->{ELEMENTS}}) {
	    $res .= "\tif (ptr_$e->{NAME})\n\t\toffset = dissect_$e->{TYPE}(tvb, offset, pinfo, tree);\n\n",
	    if (defined $e->{POINTERS});
	}
    }
}


#####################################################################
# parse a union element
sub ParseUnionElement($)
{
    my($element) = shift;
    
#    $res .= "int dissect_$element->{DATA}->{TYPE}()\n{\n";

#    $res .= "}\n\n";

    $res .= "\tcase $element->{DATA}->{NAME}: \n";
    $res .= "\t\toffset = dissect_$element->{DATA}->{TYPE}(tvb, offset, pinfo, tree);\n\t\tbreak;\n";

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

    $res .= "static int dissect_$typedef->{NAME}(tvbuff_t *tvb, int offset,\
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

    if (@{$arg->{PROPERTIES}}[0] =~ /$io/) {
	my $is_pol = 0;
	    
	# Arg is a policy handle - no pointer
	    
	foreach my $prop (@{$arg->{PROPERTIES}}) {
	    if ($prop =~ /context_handle/) {
		$res .= "\toffset = dissect_policy_hnd(tvb, offset, pinfo, tree);\n";
		$is_pol = 1;
	    }
	}
	
	if (!$is_pol) {
	    if ($arg->{POINTERS}) {
		$res .= "\tptr_$arg->{NAME} = dissect_dcerpc_ptr(tvb, offset, pinfo, tree);\n";
		$res .= "\tif (ptr_$arg->{NAME})\
\t\toffset = dissect_dcerpc_$arg->{TYPE}(tvb, offset, pinfo, tree, NULL);\n\n";
	    } else {
		$res .= "\toffset = dissect_dcerpc_$arg->{TYPE}(tvb, offset, pinfo, tree);\n";
	    }
	}
    }
}
    
#####################################################################
# parse a function
sub ParseFunction($)
{ 
    my($function) = shift;

    # Input function

    $res .= "static int $function->{NAME}_q(tvbuff_t *tvb, int offset,\
\tpacket_info *pinfo, proto_tree *tree)\n{\n";

    foreach my $arg (@{$function->{DATA}}) {
	ParseFunctionArg($arg, "in");
    }
    
    $res .= "\n\treturn 0;\n}\n\n";
    
    # Output function

    $res .= "static int $function->{NAME}_r(tvbuff_t *tvb, int offset,\
\tpacket_info *pinfo, proto_tree *tree)\n{\n";

    foreach my $arg (@{$function->{DATA}}) {
	ParseFunctionArg($arg, "out");
    }

    $res .= "\n\toffset = dissect_ntstatus(tvb, offset, pinfo, tree);\n";

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
