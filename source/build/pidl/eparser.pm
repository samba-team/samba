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
    return 1, if ($type eq "wchar_t");

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
		return $d->{$k}, if ($k eq $p);
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
# parse an array - called in buffers context
sub ParseArray($)
{
    my($elt) = shift;

    $res .= "\tfor (i = 0; i < count; i++) {\n";
    if (is_scalar_type($elt)) {
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
# parse a structure element
sub ParseElement($$)
{
    my($elt) = shift;
    my($flags) = shift;

    # Arg is a policy handle
	    
    if (has_property($elt->{PROPERTIES}, "context_handle")) {
	$res .= "\toffset = prs_policy_hnd(tvb, offset, pinfo, tree);\n";
	return;
    }

    # Parse type

    if ($flags =~ /scalars/) {

	# Pointers are scalars

	if ($elt->{POINTERS}) {
	    $res .= "\t\toffset = prs_ptr(tvb, offset, pinfo, tree, &ptr_$elt->{NAME}, \"$elt->{NAME}\");\n";
	} else {

	    # Simple type are scalars too

	    if (is_scalar_type($elt->{TYPE})) {
		$res .= "\t\toffset = prs_$elt->{TYPE}(tvb, offset, pinfo, tree, NULL, \"$elt->{NAME}\");\n\n";
	    }
	}

    }

    if ($flags =~ /buffers/) {

	# Scalars are not buffers, except if they are pointed to

	if (!is_scalar_type($elt->{TYPE}) || $elt->{POINTERS}) {

	    # If we have a pointer, check it

	    if ($elt->{POINTERS}) {
		$res .= "\t\tif (ptr_$elt->{NAME})\n\t";
	    }
	    
	    if (has_property($elt->{PROPERTIES}, "size_is")) {
		ParseArray($elt);
	    } else {
		$res .= "\t\toffset = prs_$elt->{TYPE}(tvb, offset, pinfo, tree, ";
		if (is_scalar_type($elt->{TYPE})) {
		    $res .= "NULL, ";
		} else {
		    $res .= "flags, ";
		}
		$res .= "\"$elt->{NAME}\");\n\n";
	    }
	}
    }

    return;
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
	}	

	$res .= "\t}\n\n";

	# Parse buffers

	$res .= "\tif (flags & PARSE_BUFFERS) {\n";

	foreach my $e (@{$struct->{ELEMENTS}}) {
	    ParseElement($e, "buffers");
	}

	$res .= "\t}\n\n";
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

    $res .= "static int prs_$typedef->{NAME}(tvbuff_t *tvb, int offset,\
\tpacket_info *pinfo, proto_tree *tree, int flags, char *name)\n{\n";
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

	# For some reason, pointers to elements in function definitions
	# aren't parsed.

	if (defined($arg->{POINTERS}) && !is_scalar_type($arg->{TYPE})) {
	    $arg->{POINTERS} -= 1, if ($arg->{POINTERS} > 0);
	    delete($arg->{POINTERS}), if ($arg->{POINTERS} == 0);
	}

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
    
    $res .= "\n\treturn offset;\n}\n\n";
    
    # Output function

    $res .= "static int $function->{NAME}_r(tvbuff_t *tvb, int offset,\
\tpacket_info *pinfo, proto_tree *tree, char *drep)\n{\n";

    foreach my $arg (@{$function->{DATA}}) {
	ParseFunctionArg($arg, "out");
    }

    $res .= "\n\toffset = prs_ntstatus(tvb, offset, pinfo, tree);\n";

    $res .= "\n\treturn offset;\n}\n\n";

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
