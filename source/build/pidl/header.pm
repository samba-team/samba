###################################################
# create C header files for an IDL structure
# Copyright tridge@samba.org 2000
# released under the GNU GPL

package IdlHeader;

use strict;
use needed;

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
sub HeaderProperties($)
{
    my($props) = shift;

    return;

    foreach my $d (@{$props}) {
	if (ref($d) ne "HASH") {
	    pidl "/* [$d] */ ";
	} else {
	    foreach my $k (keys %{$d}) {
		pidl "/* [$k($d->{$k})] */ ";
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
    pidl tabs();
    HeaderType($element, $element->{TYPE}, "");
    pidl " ";
    if ($element->{POINTERS} && 
	$element->{TYPE} ne "string") {
	    my($n) = $element->{POINTERS};
	    for (my($i)=$n; $i > 0; $i--) {
		    pidl "*";
	    }
    }
    if (defined $element->{ARRAY_LEN} && 
	!util::is_constant($element->{ARRAY_LEN}) &&
	!$element->{POINTERS}) {
	    # conformant arrays are ugly! I choose to implement them with
	    # pointers instead of the [1] method
	    pidl "*";
    }
    pidl "$element->{NAME}";
    if (defined $element->{ARRAY_LEN} && util::is_constant($element->{ARRAY_LEN})) {
	    pidl "[$element->{ARRAY_LEN}]";
    }
    pidl ";\n";
}

#####################################################################
# parse a struct
sub HeaderStruct($$)
{
    my($struct) = shift;
    my($name) = shift;
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
    my($enum) = shift;
    my($name) = shift;

    util::register_enum($enum, $name);

    pidl "\nenum $name {\n";
    $tab_depth++;
    my $els = \@{$enum->{ELEMENTS}};
    foreach my $i (0 .. $#{$els}-1) {
	    my $e = ${$els}[$i];
	    tabs();
	    chomp $e;
	    pidl "$e,\n";
    }

    my $e = ${$els}[$#{$els}];
    tabs();
    chomp $e;
    if ($e !~ /^(.*?)\s*$/) {
	    die "Bad enum $name\n";
    }
    pidl "$1\n";
    $tab_depth--;
    pidl "}";
}

#####################################################################
# parse a bitmap
sub HeaderBitmap($$)
{
    my($bitmap) = shift;
    my($name) = shift;

    util::register_bitmap($bitmap, $name);

    pidl "\n/* bitmap $name */\n";

    my $els = \@{$bitmap->{ELEMENTS}};
    foreach my $i (0 .. $#{$els}) {
	    my $e = ${$els}[$i];
	    chomp $e;
	    pidl "#define $e\n";
    }

    pidl "\n";
}

#####################################################################
# parse a union
sub HeaderUnion($$)
{
	my($union) = shift;
	my($name) = shift;
	my %done = ();

	(defined $union->{PROPERTIES}) && HeaderProperties($union->{PROPERTIES});
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
	my $e = shift;
	my($data) = shift;
	my($name) = shift;
	if (ref($data) eq "HASH") {
		($data->{TYPE} eq "ENUM") &&
		    HeaderEnum($data, $name);
		($data->{TYPE} eq "BITMAP") &&
		    HeaderBitmap($data, $name);
		($data->{TYPE} eq "STRUCT") &&
		    HeaderStruct($data, $name);
		($data->{TYPE} eq "UNION") &&
		    HeaderUnion($data, $name);
		return;
	}
	if ($data =~ "string") {
		pidl "const char *";
	} elsif (util::is_enum($e->{TYPE})) {
		pidl "enum $data";
	} elsif (util::is_bitmap($e->{TYPE})) {
		my $bitmap = util::get_bitmap($e->{TYPE});
		pidl util::bitmap_type_decl($bitmap);
	} elsif (NdrParser::is_scalar_type($data)) {
		pidl util::map_type($data);
	} elsif (util::has_property($e, "switch_is")) {
		pidl "union $data";
	} else {
		pidl "struct $data";
	}
}

#####################################################################
# parse a declare
sub HeaderDeclare($)
{
	my($declare) = shift;

	if ($declare->{DATA}->{TYPE} eq "ENUM") {
		util::register_enum($declare, $declare->{NAME});
	} elsif ($declare->{DATA}->{TYPE} eq "BITMAP") {
		util::register_bitmap($declare, $declare->{NAME});
	}
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

    if (needed::is_needed("ndr_size_$d->{NAME}")) {
	    if ($d->{DATA}{TYPE} eq "STRUCT") {
		    pidl "size_t ndr_size_$d->{NAME}(const struct $d->{NAME} *r, int flags);\n";
	    }
	    if ($d->{DATA}{TYPE} eq "UNION") {
		    pidl "size_t ndr_size_$d->{NAME}(const union $d->{NAME} *r, uint32_t level, int flags);\n";
	    }
    }

    if (!util::has_property($d, "public")) {
	    return;
    }

    if ($d->{DATA}{TYPE} eq "STRUCT") {
	    pidl "NTSTATUS ndr_push_$d->{NAME}(struct ndr_push *ndr, int ndr_flags, struct $d->{NAME} *r);\n";
	    pidl "NTSTATUS ndr_pull_$d->{NAME}(struct ndr_pull *ndr, int ndr_flags, struct $d->{NAME} *r);\n";
	    if (!util::has_property($d, "noprint")) {
		    pidl "void ndr_print_$d->{NAME}(struct ndr_print *ndr, const char *name, struct $d->{NAME} *r);\n";
	    }

    }
    if ($d->{DATA}{TYPE} eq "UNION") {
	    pidl "NTSTATUS ndr_push_$d->{NAME}(struct ndr_push *ndr, int ndr_flags, int level, union $d->{NAME} *r);\n";
	    pidl "NTSTATUS ndr_pull_$d->{NAME}(struct ndr_pull *ndr, int ndr_flags, int level, union $d->{NAME} *r);\n";
	    if (!util::has_property($d, "noprint")) {
		    pidl "void ndr_print_$d->{NAME}(struct ndr_print *ndr, const char *name, int level, union $d->{NAME} *r);\n";
	    }
    }

    if ($d->{DATA}{TYPE} eq "ENUM") {
	    pidl "NTSTATUS ndr_push_$d->{NAME}(struct ndr_push *ndr, int ndr_flags, enum $d->{NAME} r);\n";
	    pidl "NTSTATUS ndr_pull_$d->{NAME}(struct ndr_pull *ndr, int ndr_flags, enum $d->{NAME} *r);\n";
	    if (!util::has_property($d, "noprint")) {
		    pidl "void ndr_print_$d->{NAME}(struct ndr_print *ndr, const char *name, enum $d->{NAME} r);\n";
	    }
    }

    if ($d->{DATA}{TYPE} eq "BITMAP") {
    	    my $type_decl = util::bitmap_type_decl($d->{DATA});
	    pidl "NTSTATUS ndr_push_$d->{NAME}(struct ndr_push *ndr, int ndr_flags, $type_decl r);\n";
	    pidl "NTSTATUS ndr_pull_$d->{NAME}(struct ndr_pull *ndr, int ndr_flags, $type_decl *r);\n";
	    if (!util::has_property($d, "noprint")) {
		    pidl "void ndr_print_$d->{NAME}(struct ndr_print *ndr, const char *name, $type_decl r);\n";
	    }
    }
}

#####################################################################
# parse a const
sub HeaderConst($)
{
    my($const) = shift;
    if (!defined($const->{ARRAY_LEN})) {
    	pidl "#define $const->{NAME}\t( $const->{VALUE} )\n";
    } else {
    	pidl "#define $const->{NAME}\t $const->{VALUE}\n";
    }
}

#####################################################################
# parse a function
sub HeaderFunctionInOut($$)
{
    my($fn) = shift;
    my($prop) = shift;

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
    my($fn) = shift;
    my($prop) = shift;

    if ($prop eq "out" && $fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
	    return 1;
    }

    foreach my $e (@{$fn->{ELEMENTS}}) {
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
	    if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		    tabs();
		    pidl util::map_type($fn->{RETURN_TYPE}) . " result;\n";
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
	my $interface = shift;
    my $fn = shift;
    my $name = $fn->{NAME};
	
    pidl "void ndr_print_$name(struct ndr_print *ndr, const char *name, int flags, struct $name *r);\n";

	if (util::has_property($interface, "object")) {
		pidl "NTSTATUS dcom_$interface->{NAME}_$name (struct dcom_interface_p *d, TALLOC_CTX *mem_ctx, struct $name *r);\n";
	} else {
	    pidl "NTSTATUS dcerpc_$name(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct $name *r);\n";
    	pidl "struct rpc_request *dcerpc_$name\_send(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct $name *r);\n";
	}
    pidl "\n";
}


#####################################################################
# generate vtable structure for DCOM interface
sub HeaderVTable($)
{
	my $interface = shift;
	pidl "struct dcom_$interface->{NAME}_vtable {\n";
 	if (defined($interface->{BASE})) {
		pidl "\tstruct dcom_$interface->{BASE}\_vtable base;\n";
	}

	my $data = $interface->{DATA};
	foreach my $d (@{$data}) {
		pidl "\tNTSTATUS (*$d->{NAME}) (struct dcom_interface_p *d, TALLOC_CTX *mem_ctx, struct $d->{NAME} *r);\n" if ($d->{TYPE} eq "FUNCTION");
	}
	pidl "};\n\n";
}


#####################################################################
# parse the interface definitions
sub HeaderInterface($)
{
    my($interface) = shift;
    my($data) = $interface->{DATA};

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

    foreach my $d (@{$data}) {
	    if ($d->{TYPE} eq "FUNCTION") {
		    my $u_name = uc $d->{NAME};
			pidl "#define DCERPC_$u_name (";
		
			if (defined($interface->{BASE})) {
				pidl "DCERPC_" . uc $interface->{BASE} . "_CALL_COUNT + ";
			}
			
		    pidl sprintf("0x%02x", $count) . ")\n";
		    $count++;
	    }
    }

	pidl "\n#define DCERPC_" . uc $interface->{NAME} . "_CALL_COUNT (";
	
	if (defined($interface->{BASE})) {
		pidl "DCERPC_" . uc $interface->{BASE} . "_CALL_COUNT + ";
	}
	
	pidl "$count)\n\n";

    foreach my $d (@{$data}) {
	($d->{TYPE} eq "CONST") &&
	    HeaderConst($d);
	($d->{TYPE} eq "DECLARE") &&
	    HeaderDeclare($d);
	($d->{TYPE} eq "TYPEDEF") &&
	    HeaderTypedef($d);
	($d->{TYPE} eq "TYPEDEF") &&
	    HeaderTypedefProto($d);
	($d->{TYPE} eq "FUNCTION") &&
	    HeaderFunction($d);
	($d->{TYPE} eq "FUNCTION") &&
	    HeaderFnProto($interface, $d);
    }
	
	(util::has_property($interface, "object")) &&
		HeaderVTable($interface);

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
		    needed::BuildNeeded($x);
		    HeaderInterface($x);
	    }
    }
    return $res;
}

1;
