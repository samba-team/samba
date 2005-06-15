###################################################
# create C header files for an IDL structure
# Copyright tridge@samba.org 2000
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package NdrHeader;

use strict;
use pidl::typelist;

my($res);
my($tab_depth);

sub pidl ($)
{
	$res .= shift;
}

sub tabs()
{
	for (my($i)=0; $i < $tab_depth; $i++) {
		pidl "\t";
	}
}

#####################################################################
# parse a properties list
sub HeaderProperties($$)
{
    my($props,$ignores) = @_;
	my $ret = "";

	return; 

    foreach my $d (keys %{$props}) {
		next if ($ignores->{$d});
		if($props->{$d} ne "1") {
			$ret.= "$d(" . $props->{$d} . "),";
		} else {
			$ret.="$d,";
		}
	}

	if ($ret) {
		pidl "/* [" . substr($ret, 0, -1) . "] */";
	}
}

#####################################################################
# parse a structure element
sub HeaderElement($)
{
	my($element) = shift;

	if (defined $element->{PROPERTIES}) {
		HeaderProperties($element->{PROPERTIES}, {"in" => 1, "out" => 1});
	}
	pidl tabs();
	HeaderType($element, $element->{TYPE}, "");
	pidl " ";
	my $prefix = "";
	my $postfix = "";
	foreach my $l (@{$element->{LEVELS}}) 
	{
		if (($l->{TYPE} eq "POINTER")) {
			my $nl = Ndr::GetNextLevel($element, $l);
			$nl = Ndr::GetNextLevel($element, $nl) if ($nl->{TYPE} eq "SUBCONTEXT");
			next if ($nl->{TYPE} eq "DATA" and typelist::scalar_is_reference($nl->{DATA_TYPE}));
			$prefix .= "*";
		} elsif (($l->{TYPE} eq "ARRAY")) {
			my $pl = Ndr::GetPrevLevel($element, $l);
			next if ($pl and $pl->{TYPE} eq "POINTER");

			if ($l->{IS_FIXED}) { 
				$postfix .= "[$l->{SIZE_IS}]"; 
			} else {
				$prefix .= "*";
			}
		} elsif ($l->{TYPE} eq "DATA") {
    			pidl "$prefix$element->{NAME}$postfix";
		}
	}

	if (defined $element->{ARRAY_LEN}[0] && util::is_constant($element->{ARRAY_LEN}[0])) {
		pidl "[$element->{ARRAY_LEN}[0]]";
	}
	pidl ";\n";
}

#####################################################################
# parse a struct
sub HeaderStruct($$)
{
    my($struct,$name) = @_;
    pidl "\nstruct $name {\n";
    $tab_depth++;
    my $el_count=0;
    if (defined $struct->{ELEMENTS}) {
		foreach my $e (@{$struct->{ELEMENTS}}) {
		    HeaderElement($e);
		    $el_count++;
		}
    }
    if ($el_count == 0) {
	    # some compilers can't handle empty structures
	    pidl "\tchar _empty_;\n";
    }
    $tab_depth--;
    pidl "}";
}

#####################################################################
# parse a enum
sub HeaderEnum($$)
{
    my($enum,$name) = @_;
    my $first = 1;

    if (not util::useUintEnums()) {
    	pidl "\nenum $name {\n";
	$tab_depth++;
	foreach my $e (@{$enum->{ELEMENTS}}) {
 	    unless ($first) { pidl ",\n"; }
	    $first = 0;
	    tabs();
	    pidl $e;
	}
	pidl "\n";
	$tab_depth--;
	pidl "}";
    } else {
        my $count = 0;
	pidl "\nenum $name { __donnot_use_enum_$name=0x7FFFFFFF};\n";
	my $with_val = 0;
	my $without_val = 0;
	foreach my $e (@{$enum->{ELEMENTS}}) {
	    my $t = "$e";
	    my $name;
	    my $value;
	    if ($t =~ /(.*)=(.*)/) {
	    	$name = $1;
	    	$value = $2;
		$with_val = 1;
		die ("you can't mix enum member with values and without values when using --uint-enums!")
			unless ($without_val == 0);
	    } else {
	    	$name = $t;
	    	$value = $count++;
		$without_val = 1;
		die ("you can't mix enum member with values and without values when using --uint-enums!")
			unless ($with_val == 0);
	    }
	    pidl "#define $name ( $value )\n";
	}
	pidl "\n";
    }
}

#####################################################################
# parse a bitmap
sub HeaderBitmap($$)
{
    my($bitmap,$name) = @_;

    pidl "\n/* bitmap $name */\n";

    foreach my $e (@{$bitmap->{ELEMENTS}})
    {
	    pidl "#define $e\n";
    }

    pidl "\n";
}

#####################################################################
# parse a union
sub HeaderUnion($$)
{
	my($union,$name) = @_;
	my %done = ();

	if (defined $union->{PROPERTIES}) {
		HeaderProperties($union->{PROPERTIES}, {});
	}
	pidl "\nunion $name {\n";
	$tab_depth++;
	foreach my $e (@{$union->{ELEMENTS}}) {
		if ($e->{TYPE} ne "EMPTY") {
			if (! defined $done{$e->{NAME}}) {
				HeaderElement($e);
			}
			$done{$e->{NAME}} = 1;
		}
	}
	$tab_depth--;
	pidl "}";
}

#####################################################################
# parse a type
sub HeaderType($$$)
{
	my($e,$data,$name) = @_;
	if (ref($data) eq "HASH") {
		($data->{TYPE} eq "ENUM") && HeaderEnum($data, $name);
		($data->{TYPE} eq "BITMAP") && HeaderBitmap($data, $name);
		($data->{TYPE} eq "STRUCT") && HeaderStruct($data, $name);
		($data->{TYPE} eq "UNION") && HeaderUnion($data, $name);
		return;
	}

	pidl typelist::mapType($e->{TYPE});
}

#####################################################################
# parse a typedef
sub HeaderTypedef($)
{
    my($typedef) = shift;
    HeaderType($typedef, $typedef->{DATA}, $typedef->{NAME});
    pidl ";\n" unless ($typedef->{DATA}->{TYPE} eq "BITMAP");
}

#####################################################################
# prototype a typedef
sub HeaderTypedefProto($)
{
    my($d) = shift;

	my $tf = NdrParser::get_typefamily($d->{DATA}{TYPE});

    if (util::has_property($d, "gensize")) {
		my $size_args = $tf->{SIZE_FN_ARGS}->($d);
		pidl "size_t ndr_size_$d->{NAME}($size_args);\n";
    }

    return unless util::has_property($d, "public");

	my $pull_args = $tf->{PULL_FN_ARGS}->($d);
	my $push_args = $tf->{PUSH_FN_ARGS}->($d);
	my $print_args = $tf->{PRINT_FN_ARGS}->($d);
	unless (util::has_property($d, "nopush")) {
		pidl "NTSTATUS ndr_push_$d->{NAME}($push_args);\n";
	}
	unless (util::has_property($d, "nopull")) {
	    pidl "NTSTATUS ndr_pull_$d->{NAME}($pull_args);\n";
	}
    unless (util::has_property($d, "noprint")) {
	    pidl "void ndr_print_$d->{NAME}($print_args);\n";
    }
}

#####################################################################
# parse a const
sub HeaderConst($)
{
    my($const) = shift;
    if (!defined($const->{ARRAY_LEN}[0])) {
    	pidl "#define $const->{NAME}\t( $const->{VALUE} )\n";
    } else {
    	pidl "#define $const->{NAME}\t $const->{VALUE}\n";
    }
}

#####################################################################
# parse a function
sub HeaderFunctionInOut($$)
{
    my($fn,$prop) = @_;

    foreach my $e (@{$fn->{ELEMENTS}}) {
	    if (util::has_property($e, $prop)) {
		    HeaderElement($e);
	    }
    }
}

#####################################################################
# determine if we need an "in" or "out" section
sub HeaderFunctionInOut_needed($$)
{
    my($fn,$prop) = @_;

    if ($prop eq "out" && $fn->{RETURN_TYPE}) {
	    return 1;
    }

    foreach my $e (@{$fn->{ELEMENTS}}) {
	    if (util::has_property($e, $prop)) {
		    return 1;
	    }
    }

    return undef;
}

my %headerstructs = ();

#####################################################################
# parse a function
sub HeaderFunction($)
{
    my($fn) = shift;

    return if ($headerstructs{$fn->{NAME}});

    $headerstructs{$fn->{NAME}} = 1;

    pidl "\nstruct $fn->{NAME} {\n";
    $tab_depth++;
    my $needed = 0;

    if (HeaderFunctionInOut_needed($fn, "in")) {
	    tabs();
	    pidl "struct {\n";
	    $tab_depth++;
	    HeaderFunctionInOut($fn, "in");
	    $tab_depth--;
	    tabs();
	    pidl "} in;\n\n";
	    $needed++;
    }

    if (HeaderFunctionInOut_needed($fn, "out")) {
	    tabs();
	    pidl "struct {\n";
	    $tab_depth++;
	    HeaderFunctionInOut($fn, "out");
	    if ($fn->{RETURN_TYPE}) {
		    tabs();
		    pidl typelist::mapType($fn->{RETURN_TYPE}) . " result;\n";
	    }
	    $tab_depth--;
	    tabs();
	    pidl "} out;\n\n";
	    $needed++;
    }

    if (! $needed) {
	    # sigh - some compilers don't like empty structures
	    tabs();
	    pidl "int _dummy_element;\n";
    }

    $tab_depth--;
    pidl "};\n\n";
}

#####################################################################
# output prototypes for a IDL function
sub HeaderFnProto($$)
{
	my ($interface,$fn) = @_;
	my $name = $fn->{NAME};

	pidl "void ndr_print_$name(struct ndr_print *ndr, const char *name, int flags, struct $name *r);\n";

	if (defined($fn->{OPNUM})) {
		pidl "NTSTATUS dcerpc_$name(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct $name *r);\n";
   		pidl "struct rpc_request *dcerpc_$name\_send(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct $name *r);\n";
	}

	return unless util::has_property($fn, "public");

	pidl "NTSTATUS ndr_push_$name(struct ndr_push *ndr, int flags, struct $name *r);\n";
	pidl "NTSTATUS ndr_pull_$name(struct ndr_pull *ndr, int flags, struct $name *r);\n";

	pidl "\n";
}

#####################################################################
# parse the interface definitions
sub HeaderInterface($)
{
	my($interface) = shift;

	my $count = 0;

	pidl "#ifndef _HEADER_NDR_$interface->{NAME}\n";
	pidl "#define _HEADER_NDR_$interface->{NAME}\n\n";

	if (defined $interface->{PROPERTIES}->{depends}) {
		my @d = split / /, $interface->{PROPERTIES}->{depends};
		foreach my $i (@d) {
			pidl "#include \"librpc/gen_ndr/ndr_$i\.h\"\n";
		}
	}

	if (defined $interface->{PROPERTIES}->{uuid}) {
		my $name = uc $interface->{NAME};
		pidl "#define DCERPC_$name\_UUID " . 
		util::make_str($interface->{PROPERTIES}->{uuid}) . "\n";

		if(!defined $interface->{PROPERTIES}->{version}) { $interface->{PROPERTIES}->{version} = "0.0"; }
		pidl "#define DCERPC_$name\_VERSION $interface->{PROPERTIES}->{version}\n";

		pidl "#define DCERPC_$name\_NAME \"$interface->{NAME}\"\n";

		if(!defined $interface->{PROPERTIES}->{helpstring}) { $interface->{PROPERTIES}->{helpstring} = "NULL"; }
		pidl "#define DCERPC_$name\_HELPSTRING $interface->{PROPERTIES}->{helpstring}\n";

		pidl "\nextern const struct dcerpc_interface_table dcerpc_table_$interface->{NAME};\n";
		pidl "NTSTATUS dcerpc_server_$interface->{NAME}_init(void);\n\n";
	}

	foreach my $d (@{$interface->{FUNCTIONS}}) {
		next if not defined($d->{OPNUM});
		my $u_name = uc $d->{NAME};
		pidl "#define DCERPC_$u_name (";
	
		if (defined($interface->{BASE})) {
			pidl "DCERPC_" . uc $interface->{BASE} . "_CALL_COUNT + ";
		}

		if ($d->{OPNUM} != $count) {
			die ("Function ".$d->{NAME}." has: wrong opnum [".$d->{OPNUM}."] should be [".$count."]");
		}

		pidl sprintf("0x%02x", $count) . ")\n";
		$count++;
	}

	pidl "\n#define DCERPC_" . uc $interface->{NAME} . "_CALL_COUNT (";
	
	if (defined($interface->{BASE})) {
		pidl "DCERPC_" . uc $interface->{BASE} . "_CALL_COUNT + ";
	}
	
	pidl "$count)\n\n";

	foreach my $d (@{$interface->{CONSTS}}) {
		HeaderConst($d);
	}

	foreach my $d (@{$interface->{TYPEDEFS}}) {
		HeaderTypedef($d);
		HeaderTypedefProto($d);
	}

	foreach my $d (@{$interface->{FUNCTIONS}}) {
		HeaderFunction($d);
		HeaderFnProto($interface, $d);
	}

	pidl "#endif /* _HEADER_NDR_$interface->{NAME} */\n";
}

#####################################################################
# parse a parsed IDL into a C header
sub Parse($)
{
    my($idl) = shift;
    $tab_depth = 0;

	$res = "";
    pidl "/* header auto-generated by pidl */\n\n";
    foreach my $x (@{$idl}) {
	    if ($x->{TYPE} eq "INTERFACE") {
		    HeaderInterface($x);
	    }
    }
    return $res;
}

1;
