###################################################
# create C header files for an IDL structure
# Copyright tridge@samba.org 2000
# released under the GNU GPL
package IdlHeader;

use Data::Dumper;

my($res);
my($tab_depth);

sub tabs()
{
	for (my($i)=0; $i < $tab_depth; $i++) {
		$res .= "\t";
	}
}

#####################################################################
# parse a properties list
sub HeaderProperties($)
{
    my($props) = shift;

    return;

    foreach my $d (@{$props}) {
	if (ref($d) ne "HASH") {
	    $res .= "/* [$d] */ ";
	} else {
	    foreach my $k (keys %{$d}) {
		$res .= "/* [$k($d->{$k})] */ ";
	    }
	}
    }
}

#####################################################################
# parse a structure element
sub HeaderElement($)
{
    my($element) = shift;

    if (util::has_property($element, "struct_len")) {
	    # a struct_len is an internal artifact - it is put on the 
	    # wire but not exposed via the api, which means it does 
	    # not appear in the header file
	    return;
    }


    (defined $element->{PROPERTIES}) && HeaderProperties($element->{PROPERTIES});
    $res .= tabs();
    HeaderType($element, $element->{TYPE}, "");
    $res .= " ";
    if ($element->{POINTERS}) {
	    my($n) = $element->{POINTERS};
	    for (my($i)=$n; $i > 0; $i--) {
		    $res .= "*";
	    }
    }
    if (defined $element->{ARRAY_LEN} &&
	$element->{ARRAY_LEN} eq "*") {
	    $res .= "*";
    }
    $res .= "$element->{NAME}";
    if (defined $element->{ARRAY_LEN} &&
	$element->{ARRAY_LEN} ne "*") {
	    $res .= "[$element->{ARRAY_LEN}]";
    }
    $res .= ";\n";
}

#####################################################################
# parse a struct
sub HeaderStruct($$)
{
    my($struct) = shift;
    my($name) = shift;
    $res .= "struct $name {\n";
    $tab_depth++;
    if (defined $struct->{ELEMENTS}) {
	foreach my $e (@{$struct->{ELEMENTS}}) {
	    HeaderElement($e);
	}
    }
    $tab_depth--;
    $res .= "}";
}


#####################################################################
# parse a union element
sub HeaderUnionElement($)
{
    my($element) = shift;
    $res .= "/* [case($element->{CASE})] */ ";
    HeaderElement($element->{DATA});
}

#####################################################################
# parse a union
sub HeaderUnion($$)
{
    my($union) = shift;
    my($name) = shift;
    (defined $union->{PROPERTIES}) && HeaderProperties($union->{PROPERTIES});
    $res .= "union $name {\n";
    foreach my $e (@{$union->{DATA}}) {
	HeaderUnionElement($e);
    }
    $res .= "}";
}

#####################################################################
# parse a type
sub HeaderType($$$)
{
	my $e = shift;
	my($data) = shift;
	my($name) = shift;
	if (ref($data) eq "HASH") {
		($data->{TYPE} eq "STRUCT") &&
		    HeaderStruct($data, $name);
		($data->{TYPE} eq "UNION") &&
		    HeaderUnion($data, $name);
		return;
	}
	if ($data =~ "unistr") {
		$res .= "const char";
	} elsif (util::is_scalar_type($data)) {
		$res .= "$data";
	} elsif (util::has_property($e, "switch_is")) {
		$res .= "union $data";
	} else {
		$res .= "struct $data";
	}
}

#####################################################################
# parse a typedef
sub HeaderTypedef($)
{
    my($typedef) = shift;
    HeaderType($typedef, $typedef->{DATA}, $typedef->{NAME});
    $res .= ";\n\n";
}

#####################################################################
# parse a function
sub HeaderFunctionInOut($$)
{
    my($fn) = shift;
    my($prop) = shift;
    foreach my $e (@{$fn->{DATA}}) {
	    if (util::has_property($e, $prop)) {
		    HeaderElement($e);
	    }
    }
}


#####################################################################
# parse a function
sub HeaderFunction($)
{
    my($fn) = shift;
    $res .= "struct $fn->{NAME} {\n";
    $tab_depth++;
    tabs();
    $res .= "struct {\n";
    $tab_depth++;
    HeaderFunctionInOut($fn, "in");
    $tab_depth--;
    tabs();
    $res .= "} in;\n\n";
    tabs();
    $res .= "struct {\n";
    $tab_depth++;
    HeaderFunctionInOut($fn, "out");
    if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
	    tabs();
	    $res .= "$fn->{RETURN_TYPE} result;\n";
    }
    $tab_depth--;
    tabs();
    $res .= "} out;\n\n";
    $tab_depth--;
    $res .= "};\n\n";
}

#####################################################################
# parse the interface definitions
sub HeaderInterface($)
{
    my($interface) = shift;
    my($data) = $interface->{DATA};
    foreach my $d (@{$data}) {
	($d->{TYPE} eq "TYPEDEF") &&
	    HeaderTypedef($d);
	($d->{TYPE} eq "FUNCTION") && 
	    HeaderFunction($d);
    }

    my $count = 0;

    foreach my $d (@{$data}) {
	    if ($d->{TYPE} eq "FUNCTION") {
		    $u_name = uc $d->{NAME};
		    $res .= "#define DCERPC_$u_name $count\n";
		    $count++;
	    }
    }
}


#####################################################################
# parse a parsed IDL into a C header
sub Parse($)
{
    my($idl) = shift;
    $tab_depth = 0;

    $res = "/* header auto-generated by pidl */\n\n";
    foreach my $x (@{$idl}) {
	($x->{TYPE} eq "INTERFACE") && 
	    HeaderInterface($x);
    }
    return $res;
}

1;
