###################################################
# dump function for IDL structures
# Copyright tridge@samba.org 2000
# released under the GNU GPL

package IdlDump;

use strict;

my($res);

#####################################################################
# dump a properties list
sub DumpProperties($)
{
    my($props) = shift;
    my($res);

    foreach my $d ($props) {
	foreach my $k (keys %{$d}) {
	    if ($k eq "in") {
		$res .= "[in] ";
		next;
	    }
	    if ($k eq "out") {
		$res .= "[out] ";
		next;
	    }
	    if ($k eq "ref") {
		$res .= "[ref] ";
		next;
	    }
	    $res .= "[$k($d->{$k})] ";
	}
    }
    return $res;
}

#####################################################################
# dump a structure element
sub DumpElement($)
{
    my($element) = shift;
    my($res);

    (defined $element->{PROPERTIES}) && 
	($res .= DumpProperties($element->{PROPERTIES}));
    $res .= DumpType($element->{TYPE});
    $res .= " ";
    if ($element->{POINTERS}) {
	for (my($i)=0; $i < $element->{POINTERS}; $i++) {
	    $res .= "*";
	}
    }
    $res .= "$element->{NAME}";
    (defined $element->{ARRAY_LEN}) && ($res .= "[$element->{ARRAY_LEN}]");

    return $res;
}

#####################################################################
# dump a struct
sub DumpStruct($)
{
    my($struct) = shift;
    my($res);

    $res .= "struct {\n";
    if (defined $struct->{ELEMENTS}) {
	foreach my $e (@{$struct->{ELEMENTS}}) {
	    $res .= DumpElement($e);
	    $res .= ";\n";
	}
    }
    $res .= "}";
    
    return $res;
}


#####################################################################
# dump a union element
sub DumpUnionElement($)
{
    my($element) = shift;
    my($res);

    if ($element->{CASE} eq "default") {
	$res .= "[default] ;\n";
    } else {
	$res .= "[case($element->{CASE})] ";
	$res .= DumpElement($element->{DATA}), if defined($element->{DATA});
	$res .= ";\n";
    }

    return $res;
}

#####################################################################
# dump a union
sub DumpUnion($)
{
    my($union) = shift;
    my($res);

    (defined $union->{PROPERTIES}) && 
	($res .= DumpProperties($union->{PROPERTIES}));
    $res .= "union {\n";
    foreach my $e (@{$union->{DATA}}) {
	$res .= DumpUnionElement($e);
    }
    $res .= "}";

    return $res;
}

#####################################################################
# dump a type
sub DumpType($)
{
    my($data) = shift;
    my($res);

    if (ref($data) eq "HASH") {
	($data->{TYPE} eq "STRUCT") &&
	    ($res .= DumpStruct($data));
	($data->{TYPE} eq "UNION") &&
	    ($res .= DumpUnion($data));
    } else {
	$res .= "$data";
    }

    return $res;
}

#####################################################################
# dump a typedef
sub DumpTypedef($)
{
    my($typedef) = shift;
    my($res);

    $res .= "typedef ";
    $res .= DumpType($typedef->{DATA});
    $res .= " $typedef->{NAME};\n\n";

    return $res;
}

#####################################################################
# dump a typedef
sub DumpFunction($)
{
    my($function) = shift;
    my($first) = 1;
    my($res);

    $res .= DumpType($function->{RETURN_TYPE});
    $res .= " $function->{NAME}(\n";
    for my $d (@{$function->{DATA}}) {
	$first || ($res .= ",\n"); $first = 0;
	$res .= DumpElement($d);
    }
    $res .= "\n);\n\n";

    return $res;
}

#####################################################################
# dump a module header
sub DumpModuleHeader($)
{
    my($header) = shift;
    my($data) = $header->{DATA};
    my($first) = 1;
    my($res);

    $res .= "[\n";
    foreach my $k (keys %{$data}) {
	    $first || ($res .= ",\n"); $first = 0;
	    $res .= "$k($data->{$k})";
    }
    $res .= "\n]\n";

    return $res;
}

#####################################################################
# dump the interface definitions
sub DumpInterface($)
{
    my($interface) = shift;
    my($data) = $interface->{DATA};
    my($res);

    $res .= "interface $interface->{NAME}\n{\n";
    foreach my $d (@{$data}) {
	($d->{TYPE} eq "TYPEDEF") &&
	    ($res .= DumpTypedef($d));
	($d->{TYPE} eq "FUNCTION") &&
	    ($res .= DumpFunction($d));
    }
    $res .= "}\n";

    return $res;
}


#####################################################################
# dump a parsed IDL structure back into an IDL file
sub Dump($)
{
    my($idl) = shift;
    my($res);

    $res = "/* Dumped by pidl */\n\n";
    foreach my $x (@{$idl}) {
	($x->{TYPE} eq "MODULEHEADER") && 
	    ($res .= DumpModuleHeader($x));
	($x->{TYPE} eq "INTERFACE") && 
	    ($res .= DumpInterface($x));
    }
    return $res;
}

1;
