###################################################
# create C header files for an IDL structure
# Copyright tridge@samba.org 2000
# released under the GNU GPL

package IdlHeader;

use strict;

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

    (defined $element->{PROPERTIES}) && HeaderProperties($element->{PROPERTIES});
    $res .= tabs();
    HeaderType($element, $element->{TYPE}, "");
    $res .= " ";
    if ($element->{POINTERS} && 
	$element->{TYPE} ne "string") {
	    my($n) = $element->{POINTERS};
	    for (my($i)=$n; $i > 0; $i--) {
		    $res .= "*";
	    }
    }
    if (defined $element->{ARRAY_LEN} && 
	!util::is_constant($element->{ARRAY_LEN}) &&
	!$element->{POINTERS}) {
	    # conformant arrays are ugly! I choose to implement them with
	    # pointers instead of the [1] method
	    $res .= "*";
    }
    $res .= "$element->{NAME}";
    if (defined $element->{ARRAY_LEN} && util::is_constant($element->{ARRAY_LEN})) {
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
    $res .= "\nstruct $name {\n";
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
# parse a struct
sub HeaderEnum($$)
{
    my($enum) = shift;
    my($name) = shift;
    $res .= "\nenum $name {\n";
    $tab_depth++;
    my $els = \@{$enum->{ELEMENTS}};
    foreach my $i (0 .. $#{$els}-1) {
	    my $e = ${$els}[$i];
	    tabs();
	    chomp $e;
	    $res .= "$e,\n";
    }

    my $e = ${$els}[$#{$els}];
    tabs();
    chomp $e;
    if ($e !~ /^(.*?)\s*$/) {
	    die "Bad enum $name\n";
    }
    $res .= "$1\n";
    $tab_depth--;
    $res .= "}";
}


#####################################################################
# parse a union
sub HeaderUnion($$)
{
	my($union) = shift;
	my($name) = shift;
	my %done = ();

	(defined $union->{PROPERTIES}) && HeaderProperties($union->{PROPERTIES});
	$res .= "\nunion $name {\n";
	$tab_depth++;
	foreach my $e (@{$union->{DATA}}) {
		if ($e->{TYPE} eq "UNION_ELEMENT") {
			if (! defined $done{$e->{DATA}->{NAME}}) {
				HeaderElement($e->{DATA});
			}
			$done{$e->{DATA}->{NAME}} = 1;
		}
	}
	$tab_depth--;
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
		($data->{TYPE} eq "ENUM") &&
		    HeaderEnum($data, $name);
		($data->{TYPE} eq "STRUCT") &&
		    HeaderStruct($data, $name);
		($data->{TYPE} eq "UNION") &&
		    HeaderUnion($data, $name);
		return;
	}
	if ($data =~ "string") {
		$res .= "const char *";
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
    $res .= ";\n";
}

#####################################################################
# parse a typedef
sub HeaderConst($)
{
    my($const) = shift;
    $res .= "#define $const->{NAME}\t( $const->{VALUE} )\n";
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
# determine if we need an "in" or "out" section
sub HeaderFunctionInOut_needed($$)
{
    my($fn) = shift;
    my($prop) = shift;

    if ($prop eq "out" && $fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
	    return 1;
    }

    foreach my $e (@{$fn->{DATA}}) {
	    if (util::has_property($e, $prop)) {
		    return 1;
	    }
    }

    return undef;
}


#####################################################################
# parse a function
sub HeaderFunction($)
{
    my($fn) = shift;

    $res .= "\nstruct $fn->{NAME} {\n";
    $tab_depth++;
    my $needed = 0;

    if (HeaderFunctionInOut_needed($fn, "in")) {
	    tabs();
	    $res .= "struct {\n";
	    $tab_depth++;
	    HeaderFunctionInOut($fn, "in");
	    $tab_depth--;
	    tabs();
	    $res .= "} in;\n\n";
	    $needed++;
    }

    if (HeaderFunctionInOut_needed($fn, "out")) {
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
	    $needed++;
    }

    if (! $needed) {
	    # sigh - some compilers don't like empty structures
	    tabs();
	    $res .= "int _dummy_element;\n";
    }

    $tab_depth--;
    $res .= "};\n\n";
}

#####################################################################
# parse the interface definitions
sub HeaderInterface($)
{
    my($interface) = shift;
    my($data) = $interface->{DATA};

    my $count = 0;

    $res .= "#ifndef _HEADER_NDR_$interface->{NAME}\n";
    $res .= "#define _HEADER_NDR_$interface->{NAME}\n\n";

    if (defined $interface->{PROPERTIES}->{uuid}) {
	    my $name = uc $interface->{NAME};
	    $res .= "#define DCERPC_$name\_UUID \"$interface->{PROPERTIES}->{uuid}\"\n";

		if(!defined $interface->{PROPERTIES}->{version}) { $interface->{PROPERTIES}->{version} = "0.0"; }
	    $res .= "#define DCERPC_$name\_VERSION $interface->{PROPERTIES}->{version}\n";
	    $res .= "#define DCERPC_$name\_NAME \"$interface->{NAME}\"\n\n";
	    $res .= "extern const struct dcerpc_interface_table dcerpc_table_$interface->{NAME};\n";
	    $res .= "NTSTATUS dcerpc_$interface->{NAME}_init(void);\n\n";
    }

    foreach my $d (@{$data}) {
	    if ($d->{TYPE} eq "FUNCTION") {
		    my $u_name = uc $d->{NAME};
		    $res .= "#define DCERPC_$u_name " . sprintf("0x%02x", $count) . "\n";
		    $count++;
	    }
    }

    $res .= "\n\n";

    foreach my $d (@{$data}) {
	($d->{TYPE} eq "CONST") &&
	    HeaderConst($d);
	($d->{TYPE} eq "TYPEDEF") &&
	    HeaderTypedef($d);
	($d->{TYPE} eq "FUNCTION") && 
	    HeaderFunction($d);
    }

    $res .= "#endif /* _HEADER_NDR_$interface->{NAME} */\n";
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
