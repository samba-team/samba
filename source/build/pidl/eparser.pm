###################################################
# parser generator for IDL structures
# Copyright tpot@samba.org 2001
# Copyright tridge@samba.org 2000
# released under the GNU GPL

package IdlEParser;

use strict;
use dump;

my($name);

#####################################################################
# handlers for parsing ndr argument types

sub ParamSimpleNdrType($)
{
    my($p) = shift;
    my($res);

    $res .= "\toffset = dissect_ndr_$p->{TYPE}(tvb, offset, pinfo, tree, drep, hf_$p->{NAME}_$p->{TYPE}, NULL);\n";

    return $res;
}

sub ParamPolicyHandle($)
{
    my($p) = shift;
    my($res);

    $res .= "\toffset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_policy_handle, NULL, NULL, FALSE, FALSE);\n";

    return $res;
}

sub ParamString($)
{
    my($p) = shift;
    my($res);

    $res .= "\toffset = dissect_ndr_pointer_cb(tvb, offset, pinfo, tree, drep, dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE, \"$p->{NAME}\", hf_$p->{NAME}_string, cb_wstr_postprocess, GINT_TO_POINTER(1));\n";

    return $res;
}

my %param_handlers = (
		      'uint16' => \&ParamSimpleNdrType,
		      'uint32' => \&ParamSimpleNdrType,
		      'policy_handle' => \&ParamPolicyHandle,
		      'string' => \&ParamString,
		      );

#####################################################################
# parse a function
sub ParseParameter($)
{ 
    my($p) = shift;
    my($res);

    if (defined($param_handlers{$p->{TYPE}})) {
	$res .= &{$param_handlers{$p->{TYPE}}}($p);
	return $res;
    }

    $res .= "\tproto_tree_add_text(tree, tvb, offset, -1, \"Unhandled IDL type '$p->{TYPE}'\");\n";

    return $res;
}

#####################################################################
# parse a function
sub ParseFunction($)
{ 
    my($f) = shift;
    my($res);

    $res .= "/*\n\n";
    $res .= IdlDump::DumpFunction($f);
    $res .= "*/\n\n";

    # Request function

    $res .= "static int\n";
    $res .= "$f->{NAME}_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)\n";
    $res .= "{\n";

    my($d);
    foreach $d (@{$f->{DATA}}) {
	$res .= ParseParameter($d), if defined($d->{PROPERTIES}{in});
    }

    $res .= "\n\treturn offset;\n";
    $res .= "}\n\n";

    # Response function

    $res .= "static int\n";
    $res .= "$f->{NAME}_resp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)\n";
    $res .= "{\n";

    foreach $d (@{$f->{DATA}}) {
	$res .= ParseParameter($d), if defined($d->{PROPERTIES}{out});
    }

    $res .= "\n\toffset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, hf_rc, NULL);\n\n";

    $res .= "\treturn offset;\n";
    $res .= "}\n\n";

    return $res;
}

#####################################################################
# parse a function
sub ParseEnum($$)
{
    my($name) = shift;
    my($enum) = shift;

    return "/* Enum $name */\n\n";
}

#####################################################################
# parse a function
sub ParseStruct($$)
{
    my($name) = shift;
    my($struct) = shift;

    return "/* Struct $name */\n\n";
}

#####################################################################
# parse a function
sub ParseUnion($$)
{
    my($name) = shift;
    my($union) = shift;

    return "/* Union $name */\n\n";
}

#####################################################################
# parse a function
sub ParseTypedef($)
{ 
    my($typedef) = shift;
    my($data) = $typedef->{DATA};
    my($res) = "";

    $res .= ParseEnum($typedef->{NAME}, $data), if $data->{TYPE} eq "ENUM";
    $res .= ParseStruct($typedef->{NAME}, $data), if $data->{TYPE} eq "STRUCT";
    $res .= ParseUnion($typedef->{NAME}, $data), if $data->{TYPE} eq "UNION";

    return $res;
}

#####################################################################
# parse the interface definitions
sub Pass2Interface($)
{
    my($interface) = shift;
    my($data) = $interface->{DATA};
    my($res) = "";

    foreach my $d (@{$data}) {
	$res .= ParseFunction($d), if $d->{TYPE} eq "FUNCTION";
	$res .= ParseTypedef($d), if $d->{TYPE} eq "TYPEDEF";
    }

    return $res;
}

#####################################################################
# Pass 1: Stuff required before structs and functions

my %hf_info = ();		# Field info - remember for trailing stuff

sub Pass1ModuleHeader($)
{
    my($d) = shift;
    my($res) = "";

    $res .= << "EOF";
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"

extern const value_string NT_errors[];

EOF

    # UUID

    if ($d->{TYPE} eq "MODULEHEADER" and defined($d->{PROPERTIES}->{uuid})) {
	my $uuid = $d->{PROPERTIES}->{uuid};
	$res .= "static e_uuid_t uuid_dcerpc_$name = {\n";
	$res .= "\t0x" . substr($uuid, 0, 8);
	$res .= ", 0x" . substr($uuid, 9, 4);
	$res .= ", 0x" . substr($uuid, 14, 4) . ",\n";
	$res .= "\t{ 0x" . substr($uuid, 19, 2);
	$res .= ", 0x" . substr($uuid, 21, 2);
	$res .= ", 0x" . substr($uuid, 24, 2);
	$res .= ", 0x" . substr($uuid, 26, 2);
	$res .= ", 0x" . substr($uuid, 28, 2);
	$res .= ", 0x" . substr($uuid, 30, 2);
	$res .= ", 0x" . substr($uuid, 32, 2);
	$res .= ", 0x" . substr($uuid, 34, 2) . " }\n";
	$res .= "};\n\n";
	
	$res .= "static guint16 ver_dcerpc_samr = " . 
	    $d->{PROPERTIES}->{version} . ";\n\n";
    }

    return $res;
}

# Convert an idl type to an ethereal FT_* type

sub type2ft($)
{
    my($t) = shift;

    return "FT_UINT32", if ($t eq "uint32");
    return "FT_UINT16", if ($t eq "uint16");
    
    return "FT_BYTES";
}

# Select an ethereal BASE_* type for an idl type

sub type2base($)
{
    my($t) = shift;

    return "BASE_DEC", if ($t eq "uint32") or ($t eq "uint16");

    return "BASE_NONE";
}

sub Pass1Interface($)
{
    my($interface) = shift;
    my($res) = "";

    $res .= << "EOF";
static int proto_dcerpc_$name = -1;

static int hf_opnum = -1;
static int hf_rc = -1;
static int hf_policy_handle = -1;

static gint ett_dcerpc_$name = -1;

EOF

    foreach my $fn (@{$interface->{DATA}}) {
	next, if $fn->{TYPE} ne "FUNCTION";
	foreach my $args ($fn->{DATA}) {
	    foreach my $params (@{$args}) {

		my $hf_name = "$params->{NAME}_$params->{TYPE}";
		next, if defined $hf_info{$hf_name};

		# Make a note about new field

		$res .= "static int hf_$hf_name = -1;\n";
		$hf_info{$hf_name} = {
		    'ft' => type2ft($params->{TYPE}),
		    'base' => type2base($params->{TYPE}),
		    'name' => $params->{NAME}
		    };
	    }
	}
    }

    $res .= "\n";

    return $res;
}

#####################################################################
# Pass 3: trailing stuff

sub Pass3Interface($)
{
    my($interface) = shift;
    my($res) = "";

    $res .= "static dcerpc_sub_dissector dcerpc_${name}_dissectors[] = {\n";

    my $num = 0;

    foreach my $d (@{$interface->{DATA}}) {
	if ($d->{TYPE} eq "FUNCTION") {
	    # Strip module name from function name, if present
	    my $n = $d->{NAME};
	    $n = substr($d->{NAME}, length($name) + 1),
 	        if $name eq substr($d->{NAME}, 0, length($name));

	    $res .= "\t{ $num, \"$n\",\n";
	    $res .= "\t\t$d->{NAME}_rqst,\n";
	    $res .= "\t\t$d->{NAME}_resp },\n";
	    $num++;
	}
    }

    $res .= "};\n\n";

    return $res;
}

#####################################################################
# parse a parsed IDL structure back into an IDL file
sub Parse($)
{
    my($idl) = shift;
    my($res) = "/* parser auto-generated by pidl */\n\n";
    my($d);

    # Pass 0: set module name

    foreach $d (@{$idl}) {
	$name = $d->{NAME}, if ($d->{TYPE} eq "INTERFACE");
    }

    # Pass 1: header stuff

    foreach $d (@{$idl}) {
	$res .= Pass1ModuleHeader($d), if $d->{TYPE} eq "MODULEHEADER";
	$res .= Pass1Interface($d), if $d->{TYPE} eq "INTERFACE";
    }

    # Pass 2: typedefs and functions

    foreach $d (@{$idl}) {
	$res .= Pass2Interface($d), if $d->{TYPE} eq "INTERFACE";
    }

    # Pass 3: trailing stuff

    foreach $d (@{$idl}) {
	$res .= Pass3Interface($d), if $d->{TYPE} eq "INTERFACE";
    }

    my $hf_register_info = << "EOF";
\t{ &hf_opnum,
\t  { \"Operation\", \"$name.opnum\", FT_UINT16, BASE_DEC, NULL, 0x0, \"Operation\", HFILL }},
\t{ &hf_policy_handle,
\t  { \"Policy handle\", \"$name.policy\", FT_BYTES, BASE_NONE, NULL, 0x0, \"Policy handle\", HFILL }},
\t{ &hf_rc,
\t  { \"Return code\", \"$name.rc\", FT_UINT32, BASE_HEX, VALS(NT_errors), 0x0, \"Return status code\", HFILL }},
EOF

    foreach my $hf (keys(%hf_info)) {
	$hf_register_info .= "\t{ &hf_$hf,\n";
	$hf_register_info .= "\t  { \"$hf_info{$hf}{name}\", \"$hf\", $hf_info{$hf}{ft}, $hf_info{$hf}{base},\n";
	$hf_register_info .= "\t  NULL, 0, \"$hf\", HFILL }},\n";
    }
    
    my $ett_info = "/* spotty */";
    
    $res .= << "EOF";
void
proto_register_dcerpc_${name}(void)
{
        static hf_register_info hf[] = {
$hf_register_info
        };

        static gint *ett[] = {
                &ett_dcerpc_$name,
$ett_info
        };

        proto_dcerpc_$name = proto_register_protocol("$name", "$name", "$name");

        proto_register_field_array (proto_dcerpc_${name}, hf, array_length (hf));
        proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_dcerpc_$name(void)
{
        dcerpc_init_uuid(proto_dcerpc_$name, ett_dcerpc_$name, 
			 &uuid_dcerpc_$name, ver_dcerpc_$name, 
			 dcerpc_${name}_dissectors, hf_opnum);
}
EOF

    return $res;
}

1;
