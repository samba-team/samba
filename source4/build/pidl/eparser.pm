###################################################
# Samba4 parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001,2004
# released under the GNU GPL

package IdlEParser;

use strict;

# the list of needed functions
my %needed;

my $module;
my $if_uuid;
my $if_version;
my $if_endpoints;

sub pidl($)
{
	print OUT shift;
}

#####################################################################
# work out is a parse function should be declared static or not
sub fn_prefix($)
{
	my $fn = shift;
	if ($fn->{TYPE} eq "TYPEDEF") {
		if (util::has_property($fn, "public")) {
			return "";
		}
	}

	if ($fn->{TYPE} eq "FUNCTION") {
		if (util::has_property($fn, "public")) {
			return "";
		}
	}
	return "static ";
}


#####################################################################
# parse a function
sub ParseFunctionPull($)
{ 
	my($fn) = shift;
	my $static = fn_prefix($fn);

	# request function
	pidl "int $fn->{NAME}_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)\n{\n";

	pidl "\tstruct pidl_pull *ndr = pidl_pull_init(tvb, offset, pinfo, drep);\n";
	pidl "\tstruct $fn->{NAME} *r = talloc_p(NULL, struct $fn->{NAME});\n";
	pidl "\tpidl_tree ptree;\n\n";

	pidl "\tptree.proto_tree = tree;\n";
	pidl "\tptree.subtree_list = NULL;\n\n";

	pidl "\tndr_pull_$fn->{NAME}(ndr, NDR_IN, &ptree, r);\n";

	pidl "\n\treturn ndr->offset;\n";
	pidl "}\n\n";

	# response function
	pidl "int $fn->{NAME}_resp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)\n{\n";

	pidl "\tstruct pidl_pull *ndr = pidl_pull_init(tvb, offset, pinfo, drep);\n";
	pidl "\tstruct $fn->{NAME} *r = talloc_p(NULL, struct $fn->{NAME});\n";
	pidl "\tpidl_tree ptree;\n\n";

	pidl "\tptree.proto_tree = tree;\n";
	pidl "\tptree.subtree_list = NULL;\n\n";

	pidl "\tndr_pull_$fn->{NAME}(ndr, NDR_OUT, &ptree, r);\n";

	pidl "\n\treturn ndr->offset;\n";
	pidl "}\n\n";
}

#####################################################################
# produce a function call table
sub FunctionTable($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};

	pidl "static dcerpc_sub_dissector dcerpc_dissectors[] = {\n";
	my $num = 0;
	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") {
		    # Strip module name from function name, if present
		    my($n) = $d->{NAME};
		    $n = substr($d->{NAME}, length($module) + 1),
		        if $module eq substr($d->{NAME}, 0, length($module));
		    pidl "\t{ $num, \"$n\",\n";
		    pidl "\t\t$d->{NAME}_rqst,\n";
		    pidl "\t\t$d->{NAME}_resp },\n";
		    $num++;
		}
	}
	pidl "};\n\n";
}

sub type2ft($)
{
    my($t) = shift;
 
    return "FT_UINT32", if ($t eq "uint32");
    return "FT_UINT16", if ($t eq "uint16");
    return "FT_UINT8", if ($t eq "uint8");
    return "FT_BYTES";
}

# Determine the display base for an element

sub elementbase($)
{
    my($e) = shift;

    if (my $base = util::has_property($e, "display")) {
	return "BASE_" . uc($base);
    }
 
    return "BASE_DEC", if ($e->{TYPE} eq "uint32") or 
	($e->{TYPE} eq "uint16") or ($e->{TYPE} eq "uint8");
    return "BASE_NONE";
}

# Convert a IDL structure field name (e.g access_mask) to a prettier
# string like 'Access Mask'.

sub field2name($)
{
    my($field) = shift;

    $field =~ s/_/ /g;		# Replace underscores with spaces
    $field =~ s/(\w+)/\u\L$1/g;	# Capitalise each word
    
    return $field;
}

sub NeededFunction($)
{
	my $fn = shift;
	$needed{"pull_$fn->{NAME}"} = 1;
	foreach my $e (@{$fn->{DATA}}) {
		$e->{PARENT} = $fn;
		$needed{"pull_$e->{TYPE}"} = 1;

		if (util::is_scalar_type($e->{TYPE})) {
		    $needed{"hf_$e->{NAME}_$e->{TYPE}"} = {
			'name' => field2name($e->{NAME}),
			'type' => $e->{TYPE},
			'ft'   => type2ft($e->{TYPE}),
			'base' => elementbase($e)
			}, if !defined($needed{"hf_$e->{NAME}_$e->{TYPE}"});
		    $e->{PARENT} = $fn;
		} else {
		    $needed{"ett_$e->{TYPE}"} = 1;
		}
	}
}

sub NeededTypedef($)
{
	my $t = shift;
	if (util::has_property($t, "public")) {
		$needed{"pull_$t->{NAME}"} = 1;
	}

	if ($t->{DATA}->{TYPE} eq "STRUCT") {

	    for my $e (@{$t->{DATA}->{ELEMENTS}}) {
		$e->{PARENT} = $t->{DATA};
		if ($needed{"pull_$t->{NAME}"}) {
		    $needed{"pull_$e->{TYPE}"} = 1;
		}
	    
		if (util::is_scalar_type($e->{TYPE})) {
		
		    if (defined($e->{ARRAY_LEN}) or 
			util::has_property($e, "size_is")) {

			# Arrays of scalar types are FT_BYTES
		    
			$needed{"hf_$e->{NAME}_$e->{TYPE}_array"} = {
			    'name' => field2name($e->{NAME}),
			    'type' => $e->{TYPE},
			    'ft'   => "FT_BYTES",
			    'base' => elementbase($e)
			    };

		    } else {
			$needed{"hf_$e->{NAME}_$e->{TYPE}"} = {
			    'name' => field2name($e->{NAME}),
			    'type' => $e->{TYPE},
			    'ft'   => type2ft($e->{TYPE}),
			    'base' => elementbase($e)
			    };
		    }
		    
		    $e->{PARENT} = $t->{DATA};
		    
		    if ($needed{"pull_$t->{NAME}"}) {
			$needed{"pull_$e->{TYPE}"} = 1;
		    }

		} else {
		    
		    $needed{"ett_$e->{TYPE}"} = 1;
		    
		}
	    }
	}

	if ($t->{DATA}->{TYPE} eq "UNION") {
		for my $e (@{$t->{DATA}->{DATA}}) {
			$e->{PARENT} = $t->{DATA};
			if ($e->{TYPE} eq "UNION_ELEMENT") {
				if ($needed{"pull_$t->{NAME}"}) {
					$needed{"pull_$e->{DATA}->{TYPE}"} = 1;
				}
				$needed{"ett_$e->{DATA}{TYPE}"} = 1;
			}
		}

	    $needed{"ett_$t->{NAME}"} = 1;
	}
}

#####################################################################
# work out what parse functions are needed
sub BuildNeeded($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};
	foreach my $d (@{$data}) {
		($d->{TYPE} eq "FUNCTION") && 
		    NeededFunction($d);
	}
	foreach my $d (reverse @{$data}) {
		($d->{TYPE} eq "TYPEDEF") &&
		    NeededTypedef($d);
	}
}

#####################################################################
# parse the interface definitions
sub ModuleHeader($)
{
    my($h) = shift;

    $if_uuid = $h->{PROPERTIES}->{uuid};
    $if_version = $h->{PROPERTIES}->{version};
    $if_endpoints = $h->{PROPERTIES}->{endpoints};
}

#####################################################################
# Generate a header file that contains function prototypes for 
# structs and typedefs.
sub ParseHeader($$)
{
	my($idl) = shift;
	my($filename) = shift;

	open(OUT, ">$filename") || die "can't open $filename";    

	pidl "/* parser auto-generated by pidl */\n\n";

	foreach my $x (@{$idl}) {
	    if ($x->{TYPE} eq "INTERFACE") { 
		foreach my $d (@{$x->{DATA}}) {

		    # Make prototypes for [public] structures and
		    # unions.

		    if ($d->{TYPE} eq "TYPEDEF" and 
			util::has_property($d, "public")) {
			
			if ($d->{DATA}{TYPE} eq "STRUCT") { 
			    pidl "void ndr_pull_$d->{NAME}(struct ndr_pull *ndr, int ndr_flags, proto_tree *tree, struct $d->{NAME} *r);\n\n";
			}

			if ($d->{DATA}{TYPE} eq "UNION") {
			    pidl "void ndr_pull_$d->{NAME}(struct ndr_pull *ndr, int ndr_flags, proto_tree *tree, union $d->{NAME} *r, uint16 level);\n\n";
			}
		    }
		}
	    }
	}

	close(OUT);
}

#####################################################################
# rewrite autogenerated header file
sub RewriteHeader($$$)
{
    my($idl) = shift;
    my($input) = shift;
    my($output) = shift;

    %needed = ();

    # Open files

    open(IN, "<$input") || die "can't open $input for reading";
    open(OUT, ">$output") || die "can't open $output for writing";    
   
    # Read in entire file

    undef $/;

    while(<IN>) {

	# Not interested in ndr_push or ndr_print routines as they
	# define structures we aren't interested in.

	s/^NTSTATUS ndr_push.*?;\n//smg;
	s/^void ndr_print.*?;\n//smg;

	# Get rid of async send and receive function.

	s/^NTSTATUS dcerpc_.*?;\n//smg;
	s/^struct rpc_request.*?;\n\n//smg;

	# Rewrite librpc includes

	s/^\#include \"librpc\/gen_ndr\/ndr_(.*?).h\"$/\#include \"packet-dcerpc-$1.h\"/smg;

	# Convert samba fixed width types to stdint types

	s/((u)?int)([0-9]+)/$1$3_t/smg;

	# Rename struct ndr_pull to struct pidl_pull

	s/struct ndr_pull \*ndr/struct pidl_pull \*ndr/smg;

	# Change prototypes for public functions

	s/(struct pidl_pull \*ndr, int ndr_flags)/$1, pidl_tree *tree/smg;

	pidl $_;
    }

    close(OUT);   
}

#####################################################################
# rewrite autogenerated C file
sub RewriteC($$$)
{
    my($idl) = shift;
    my($input) = shift;
    my($output) = shift;

    # Open files

    open(IN, "<$input") || die "can't open $input for reading";
    open(OUT, ">$output") || die "can't open $output for writing";    
    
    # Get name of module

    foreach my $x (@{$idl}) {
	if ($x->{TYPE} eq "INTERFACE") { 
	    ModuleHeader($x);
	    $module = $x->{NAME};
	    BuildNeeded($x);
	}
    }

    pidl "#include \"eparser.h\"\n\n";

    pidl "extern const value_string NT_errors[];\n\n";

    # Declarations for hf variables

    pidl "static int hf_opnum = -1;\n";
    pidl "static int hf_ptr = -1;\n";
    pidl "static int hf_array_size = -1;\n";
    pidl "static int hf_result_NTSTATUS = -1;\n";

    foreach my $y (keys(%needed)) {
	pidl "static int $y = -1;\n", if $y =~ /^hf_/;
    }

    pidl "\n";

    foreach my $y (keys(%needed)) {
	pidl "static gint $y = -1;\n", if $y =~ /^ett_/;
    }

    pidl "\n";

    # Read in entire file for post-processing

    undef $/;

    while(<IN>) {

	# Ethereal take care of this for us.  It also makes the other
	# regular expressions easier to write and understand. 

	s/NDR_CHECK\((.*)\)/$1/g;

	# We're not interested in ndr_print or ndr_push functions.

	s/^(static )?NTSTATUS (ndr_push[^\(]+).*?^\}\n\n//smg;
	s/^void (ndr_print[^\(]+).*?^\}\n\n//smg;

	# Get rid of dcerpc interface structures and functions

	s/^static const struct dcerpc_interface_call .*?^\};\n\n//smg;	
	s/^static const char \* const ([a-z]+)_endpoint_strings.*?^\};\n\n//smg;
	s/^static const struct dcerpc_endpoint_list .*?^\};\n\n\n//smg;	
	s/^const struct dcerpc_interface_table .*?^\};\n\n//smg;	
	s/^static NTSTATUS dcerpc_ndr_([a-z]+)_init.*?^\}\n\n//smg;	
	s/^NTSTATUS dcerpc_([a-z]+)_init.*?^\}\n\n//smg;	

	# Include packet-dcerpc-foo.h instead of ndr_foo.h

	s/^\#include \".*?ndr_(.*?).h\"$/\#include \"packet-dcerpc-$1.h\"/smg;

	# Call ethereal wrapper for ndr_pull_ptr() function.

	s/(ndr_pull_ptr\(ndr, ([^\)]*?)\);)/ndr_pull_ptr(ndr, tree, hf_ptr, $2);/smg;

	# Wrap ndr_pull_array_size() - generate wrapper that won't get
	# caught by the regex for wrapping scalar values below (i.e
	# the leading space in front of the first parameter).

	s/(ndr_pull_array_(size|length)\(ndr, ([^\)]*?)\);)/ndr_pull_array_$2( ndr, tree, $3);/smg;

	# Add tree argument to ndr_pull_array()

	s/(ndr_pull_array([^\(_]*?)\(ndr, (NDR_[^,]*?), ([^\)].*?)\);)/ndr_pull_array$2( ndr, $3, tree, $4);/smg;

	s/(ndr_pull_array_([^\(]*?)\(ndr, (NDR_[^,]*?), (r->((in|out).)?([^,]*?)), (.*?)\);)/ndr_pull_array_$2( ndr, $3, tree, hf_$7_$2_array, $4, $8);/smg;
 
	# Save ndr_pull_relative[12]() calls from being wrapped by the
	# proceeding regexp.

	s/ndr_pull_(relative1|relative2)\((.*?);/ndr_pull_$1( $2;/smg;

	# Call ethereal wrappers for pull of scalar values in
	# structures and functions:
	#
	# ndr_pull_uint32(ndr, &r->in.access_mask);
	# ndr_pull_uint32(ndr, &r->idx);

	s/(ndr_pull_([^\)]*?)\(ndr, (&?r->((in|out)\.)?([^\)]*?))\);)/ndr_pull_$2(ndr, tree, hf_$6_$2, $3);/smg;

	# Pull of "internal" scalars like array sizes, levels, etcetera.

	s/(ndr_pull_(uint32|uint16)\(ndr, (&_([^\)]*?))\);)/ndr_pull_$2(ndr, tree, hf_$4, $3);/smg;

	# Call ethereal wrappers for pull of buffers in structures and
	# functions:
	#
	# ndr_pull_string(ndr, NDR_SCALARS|NDR_BUFFERS, &r->command);
	# ndr_pull_atsvc_enum_ctr(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.ctr);

	s/(ndr_pull_([^\)]*?)\(ndr, (NDR_[^,]*?), ([^\(].*?)\);)/ndr_pull_$2(ndr, $3, get_subtree(tree, \"$2\", ndr, ett_$2), $4);/smg;

	# Add proto_tree parameter to pull functions:
	#
	# static NTSTATUS ndr_pull_atsvc_JobInfo(struct ndr_pull *ndr, int ndr_flags, struct atsvc_JobInfo *r)

	s/^((static )?NTSTATUS ndr_pull_([^\(]*?)\(struct ndr_pull \*ndr, int (ndr_)?flags)/$1, proto_tree \*tree/smg;

	# Add proto_tree parameter to ndr_pull_subcontext_flags_fn()

        s/(ndr_pull_subcontext_flags_fn\(ndr)(.*?);/$1, tree$2;/smg;

	# Get rid of ndr_pull_error() calls.  Ethereal should take
	# care of buffer overruns and inconsistent array sizes for us.

	s/(return ndr_pull_error([^;]*?);)/return NT_STATUS_OK; \/\/ $1/smg;

	# Rename proto_tree args to pidl_tree

	s/(int (ndr_)?flags), proto_tree \*tree/$1, pidl_tree \*tree/smg;

	# Rename struct ndr_pull to struct pidl_pull

	s/struct ndr_pull \*ndr/struct pidl_pull \*ndr/smg;

	# Fix some internal variable declarations

        s/uint(16|32) _level/uint$1_t _level/smg;
        s/ndr_pull_([^\(]*)\(ndr, tree, hf_level, &_level\);/ndr_pull_$1(ndr, tree, hf_level_$1, &_level);/smg;
							      
	pidl $_;
    }

    # Function call table

    foreach my $x (@{$idl}) {
	if ($x->{TYPE} eq "INTERFACE") { 
	    foreach my $y (@{$x->{"INHERITED_DATA"}}) {
		($y->{TYPE} eq "FUNCTION") && ParseFunctionPull($y);
	    }

	    FunctionTable($x);
	}
    }

    # Ethereal protocol registration

    pidl "int proto_dcerpc_pidl_$module = -1;\n\n";

    pidl "static gint ett_dcerpc_$module = -1;\n\n";

    if (defined($if_uuid)) {

	pidl "static e_uuid_t uuid_dcerpc_$module = {\n";
	pidl "\t0x" . substr($if_uuid, 1, 8);
	pidl ", 0x" . substr($if_uuid, 10, 4);
	pidl ", 0x" . substr($if_uuid, 15, 4) . ",\n";
	pidl "\t{ 0x" . substr($if_uuid, 20, 2);
	pidl ", 0x" . substr($if_uuid, 22, 2);
	pidl ", 0x" . substr($if_uuid, 25, 2);
	pidl ", 0x" . substr($if_uuid, 27, 2);
	pidl ", 0x" . substr($if_uuid, 29, 2);
	pidl ", 0x" . substr($if_uuid, 31, 2);
	pidl ", 0x" . substr($if_uuid, 33, 2);
	pidl ", 0x" . substr($if_uuid, 35, 2) . " }\n";
	pidl "};\n\n";
    }

    if (defined($if_version)) {
	pidl "static guint16 ver_dcerpc_$module = " . $if_version . ";\n\n";
    }

    pidl "void proto_register_dcerpc_pidl_$module(void)\n";
    pidl "{\n";

    pidl "\tstatic hf_register_info hf[] = {\n";
    pidl "\t{ &hf_opnum, { \"Operation\", \"$module.opnum\", FT_UINT16, BASE_DEC, NULL, 0x0, \"Operation\", HFILL }},\n";
	pidl "\t{ &hf_result_NTSTATUS, { \"Return code\", \"$module.rc\", FT_UINT32, BASE_HEX, VALS(NT_errors), 0x0, \"Return status code\", HFILL }},\n";
    pidl "\t{ &hf_ptr, { \"Pointer\", \"$module.ptr\", FT_UINT32, BASE_HEX, NULL, 0x0, \"Pointer\", HFILL }},\n";

    foreach my $x (keys(%needed)) {
	next, if !($x =~ /^hf_/);
	pidl "\t{ &$x,\n";
	pidl "\t  { \"$needed{$x}{name}\", \"$x\", $needed{$x}{ft}, $needed{$x}{base}, NULL, 0, \"$x\", HFILL }},\n";
    }

    pidl "\t};\n\n";

    pidl "\tstatic gint *ett[] = {\n";
    pidl "\t\t&ett_dcerpc_$module,\n";
    foreach my $x (keys(%needed)) {
	pidl "\t\t&$x,\n", if $x =~ /^ett_/;
    }
    pidl "\t};\n\n";
    
    if (defined($if_uuid)) {

	pidl "\tproto_dcerpc_pidl_$module = proto_register_protocol(\"pidl_$module\", \"pidl_$module\", \"pidl_$module\");\n\n";

	pidl "\tproto_register_field_array(proto_dcerpc_pidl_$module, hf, array_length (hf));\n";
	pidl "\tproto_register_subtree_array(ett, array_length(ett));\n";

	pidl "}\n\n";

	pidl "void proto_reg_handoff_dcerpc_pidl_$module(void)\n";
	pidl "{\n";
	pidl "\tdcerpc_init_uuid(proto_dcerpc_pidl_$module, ett_dcerpc_$module, \n";
	pidl "\t\t&uuid_dcerpc_$module, ver_dcerpc_$module, \n";
	pidl "\t\tdcerpc_dissectors, hf_opnum);\n";
	pidl "}\n";

    } else {

	pidl "\tint proto_dcerpc;\n\n";
	pidl "\tproto_dcerpc = proto_get_id_by_filter_name(\"dcerpc\");\n";
	pidl "\tproto_register_field_array(proto_dcerpc, hf, array_length(hf));\n";
	pidl "\tproto_register_subtree_array(ett, array_length(ett));\n";

	pidl "}\n";

    }

    close(OUT);   
}

1;
