###################################################
# parser generator for IDL structures
# Copyright tpot@samba.org 2004
# released under the GNU GPL

package IdlEParser;

use strict;
use dump;
#use Data::Dumper;

#####################################################################
# Code for managing hf's

my %hf_info = ();

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

# Create a new field.  The name of the field is hf_${name}_${type} where
# name and type are taken from the IDL definition for the element.

sub AddField($$)
{
    my($name) = shift;
    my($type) = shift;
    
    my $hf_name = "${name}_${type}";
    return, if defined $hf_info{$hf_name};
    
    $hf_info{$hf_name} = {
	'name' => $name,                       # Field name
	'type' => $type,                       # Field type
	'ft'   => type2ft($type),	       # Ethereal type
	'base' => type2base($type),            # Base of type
    };
}

# Generate field definitions from %hf_info

sub EtherealFieldDefinitions()
{
    my($res) = "";

    $res .= << "EOF";
static int hf_opnum = -1;
static int hf_rc = -1;
static int hf_policy_handle = -1;
EOF

    foreach my $hf (keys(%hf_info)) {
	my($hf_name) = "$hf_info{$hf}{name}_$hf_info{$hf}{type}";
	$res .= "static int hf_$hf_name = -1;\n";
    }

    return $res;
}

# Generate field initialisers

sub EtherealFieldInitialisation($)
{
    my($module) = shift;
    my($res) = "";

    # Fields present in all parsers

    $res .= << "EOF";
\t{ &hf_opnum,
\t  { \"Operation\", \"$module.opnum\", FT_UINT16, BASE_DEC, NULL, 0x0, \"Operation\", HFILL }},
\t{ &hf_policy_handle,
\t  { \"Policy handle\", \"$module.policy\", FT_BYTES, BASE_NONE, NULL, 0x0, \"Policy handle\", HFILL }},
\t{ &hf_rc,
\t  { \"Return code\", \"$module.rc\", FT_UINT32, BASE_HEX, VALS(NT_errors), 0x0, \"Return status code\", HFILL }},
EOF

    foreach my $hf (keys(%hf_info)) {
	$res .= "\t{ &hf_$hf,\n";
	$res .= "\t  { \"$hf_info{$hf}{name}\", \"$hf\", $hf_info{$hf}{ft}, $hf_info{$hf}{base},\n";
	$res .= "\t  NULL, 0, \"$hf\", HFILL }},\n";
    }   

    return $res;
}

#####################################################################
# Code for managing subtrees

sub EtherealSubtreeDefinitions($)
{
    my($module) = shift;
    my($res) = "";

    $res .= << "EOF";
static gint ett_dcerpc_$module = -1;
EOF

    return $res;
}

sub EtherealSubtreeInitialisation()
{
    my($res) = "";
    return $res;
}

#####################################################################
# Generate dissection functions for NDR types

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

sub ParamStruct($)
{
    my($p) = shift;
    my($res);

    $res .= "\toffset = dissect_$p->{TYPE}(tvb, offset, pinfo, tree, drep);\n";

    return $res;
}

sub ParamDomSID($)
{
    my($p) = shift;
    my($res);

    $res .= "\toffset = dissect_ndr_nt_SID(tvb, offset, pinfo, tree, drep);\n";

    return $res;
}

# Index of NDR types and functions to generate code to dissect that type

my %param_handlers = (
		      'uint8' 	      => \&ParamSimpleNdrType,
		      'uint16' 	      => \&ParamSimpleNdrType,
		      'uint32' 	      => \&ParamSimpleNdrType,
		      'policy_handle' => \&ParamPolicyHandle,
		      'string' 	      => \&ParamString,
		      'dom_sid2'      => \&ParamDomSID,
		      );

sub PtrString($)
{
    my($p) = shift;
    my($res) = "";

    $res .= "/* pointer to string not supported */\n";

    return $res;
}

sub PtrSimpleNdrType($)
{
    my($p) = shift;
    my($res) = "";

    $res .= "/* pointer to $p->{TYPE} not supported */\n";

    return $res;
}

sub PtrDomSID($)
{
    my($p) = shift;
    my($res) = "";

    $res .= "/* pointer to dom_sid not supported */\n";

    return $res;
}

sub PtrSecurityDescriptor($)
{
    my($p) = shift;
    my($res) = "";

    $res .= "/* pointer to security descriptor not supported */\n";

    return $res;
}

sub PtrNotImplemented($)
{
    my($p) = shift;
    my($res) = "";

    $res .= "/* pointer to $p->{TYPE} not supported */\n";

    return $res;
}

my %ptr_handlers = (
		    'uint8'    		  => \&PtrSimpleNdrType,
		    'uint16'   		  => \&PtrSimpleNdrType,
		    'uint32'   		  => \&PtrSimpleNdrType,
		    'string'   		  => \&PtrString,
		    'dom_sid2' 		  => \&PtrDomSID,
		    'security_descriptor' => \&PtrSecurityDescriptor,
		    'lsa_SidArray' => \&PtrNotImplemented,
		    );

# Generate a parser for a NDR parameter

sub ParseParameter($)
{ 
    my($p) = shift;
    my($res);

    # Call function registered for this type

    if ($p->{POINTERS} == 1 && $p->{TYPE} ne "policy_handle") {

	if (defined($ptr_handlers{$p->{TYPE}})) {
	    $res .= &{$ptr_handlers{$p->{TYPE}}}($p);
	} else {
	    $res .= "\toffset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, dissect_$p->{TYPE}, NDR_POINTER_UNIQUE, \"$p->{TYPE} pointer\", -1);\n";
	}

	return $res;
    }

    if (defined($param_handlers{$p->{TYPE}})) {
	$res .= &{$param_handlers{$p->{TYPE}}}($p);
	return $res;
    }

    # Unknown type - make a note in the protocol tree

    $res .= "\tproto_tree_add_text(tree, tvb, offset, -1, \"Unhandled IDL type '$p->{TYPE}'\");\n";

    return $res;
}

#####################################################################
# Generate code fragment for an IDL function

sub EtherealFunction($)
{ 
    my($f) = shift;
    my($res);

    # Comment displaying IDL for this function

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
# Generate code fragment for an IDL struct

sub EtherealStruct($$)
{ 
    my($module) = shift;
    my($struct) = shift;
    my($res) = "";

    $res .= "/*\n\n";
    $res .= IdlDump::DumpStruct($struct->{DATA});
    $res .= "\n\n*/\n\n";

    $res .= << "EOF";
int dissect_$struct->{NAME}(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = offset;

    if (parent_tree) {
	item = proto_tree_add_text(parent_tree, tvb, offset, -1, "$struct->{NAME}");
	tree = proto_item_add_subtree(item, ett_dcerpc_$module);
    }

EOF

    # Parse elements

    foreach my $d (@{$struct->{DATA}->{ELEMENTS}}) {
	$res .= ParseParameter($d);
    }

$res .= << "EOF";    

    proto_item_set_len(item, offset - old_offset);

    return offset;
}

EOF

    return $res;
}

#####################################################################
# Generate code fragment for an IDL union

sub EtherealUnion($$)
{ 
    my($module) = shift;
    my($union) = shift;
    my($res) = "";

    $res .= "/*\n\n";
    $res .= IdlDump::DumpUnion($union->{DATA});
    $res .= "\n\n*/\n\n";

    $res .= << "EOF";
int dissect_$union->{NAME}(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = offset;

    if (parent_tree) {
	item = proto_tree_add_text(parent_tree, tvb, offset, -1, "$union->{NAME}");
	tree = proto_item_add_subtree(item, ett_dcerpc_$module);
    }

EOF

    # TODO: Parse elements

$res .= << "EOF";    

    proto_item_set_len(item, offset - old_offset);

    return offset;
}

EOF

    return $res;
}

#####################################################################
# Generate code fragment for an IDL typedef

sub EtherealTypedef($$)
{ 
    my($module) = shift;
    my($typedef) = shift;

    return EtherealStruct($module, $typedef), 
        if $typedef->{DATA}{TYPE} eq "STRUCT";

    return EtherealUnion($module, $typedef),
        if $typedef->{DATA}{TYPE} eq "UNION";

    return "/* Unsupported typedef $typedef->{DATA}{TYPE} " .
	"$typedef->{NAME}*/\n\n";
}

#####################################################################
# Generate code fragment for the start of the dissector

sub EtherealHeader($)
{
    my($module) = shift;
    my($res) = "";

    $res .= << "EOF";
/* parser auto-generated by pidl */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"

extern const value_string NT_errors[];

static int proto_dcerpc_$module = -1;

EOF

    return $res;
}

sub EtherealUuidRegistration($$$)
{
    my($module) = shift;
    my($uuid) = shift;
    my($uuid_version) = shift;
    my($res) = "";

    # Various objects for dissector initialisation

    $res .= "static e_uuid_t uuid_dcerpc_$module = {\n";
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
	
    $res .= "static guint16 ver_dcerpc_$module = " . $uuid_version . ";\n\n";

    return $res;
}

#####################################################################
# Generate code fragment for the tail of the dissector

sub EtherealModuleRegistration($$$)
{
    my($module) = shift;
    my($hf_register_info) = shift;
    my($ett_info) = shift;
    my($res) = "";

    $res .= << "EOF";
void
proto_register_dcerpc_${module}(void)
{
        static hf_register_info hf[] = {
$hf_register_info
        };

        static gint *ett[] = {
                &ett_dcerpc_$module,
$ett_info
        };

        proto_dcerpc_$module = proto_register_protocol("$module", "$module", "$module");

        proto_register_field_array(proto_dcerpc_$module, hf, array_length (hf));
        proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_dcerpc_$module(void)
{
        dcerpc_init_uuid(proto_dcerpc_$module, ett_dcerpc_$module, 
			 &uuid_dcerpc_$module, ver_dcerpc_$module, 
			 dcerpc_${module}_dissectors, hf_opnum);
}
EOF

    return $res;
}

#####################################################################
# Generate code fragment for DCERPC subdissector registration

sub EtherealSubdissectorRegistration($$)
{
    my($module) = shift;
    my($functions) = shift;
    my($res) = "";

    $res .= "static dcerpc_sub_dissector dcerpc_${module}_dissectors[] = {\n";

    my $num = 0;

    foreach my $name (@$functions) {
	# Strip module name from function name, if present
	my($n) = $name;
	$n = substr($name, length($module) + 1),
	    if $module eq substr($name, 0, length($module));
	
	$res .= "\t{ $num, \"$n\",\n";
	$res .= "\t\t${name}_rqst,\n";
	$res .= "\t\t${name}_resp },\n";
	$num++;
    }

    $res .= "};\n\n";

    return $res;
}

#####################################################################
# Generate an ethereal dissector from an IDL syntax tree.

sub Parse($)
{
    my($idl) = shift;
    my($res) = "";

    #
    # Phase 1 : Gather information from IDL tree
    #

    my($module) = "";
    my($uuid) = "";
    my($uuid_version) = "";
    my(@fns) = ();

    my($d, $e);

    foreach $d (@$idl) {

	# Get data from interface definition

	$module = $d->{NAME}, if $d->{TYPE} eq "INTERFACE";

	if ($d->{TYPE} eq "MODULEHEADER") {
	    $uuid = $d->{PROPERTIES}->{uuid}, 
 	        if defined($d->{PROPERTIES}->{uuid});
	    $uuid_version = $d->{PROPERTIES}->{version};
	}

	# Iterate over function definitions and register field info

	if ($d->{TYPE} eq "INTERFACE") {

	    foreach my $d (@{$d->{DATA}}) {

		if ($d->{TYPE} eq "FUNCTION") {

		    # Register function name

		    $fns[$#fns + 1] = $d->{NAME};

		    # Register function fields (parameter names)

		    foreach $e (@{$d->{DATA}}) {
			AddField($e->{NAME}, $e->{TYPE});
		    }
		}

		if ($d->{TYPE} eq "TYPEDEF") {

		    # Register structure names

		    $param_handlers{$d->{NAME}} = \&ParamStruct;

		    # Register typedef fields (element names)

		    if ($d->{DATA}->{TYPE} eq "STRUCT") {
			foreach $e (@{$d->{DATA}->{ELEMENTS}}) {
			    AddField($e->{NAME}, $e->{TYPE});
			}
		    }
		}
	    }
	}
    }

    #
    # Phase 2 : Spit out parser from fragments generated above
    #

    $res .= EtherealHeader($module);
    $res .= EtherealFieldDefinitions();
    $res .= EtherealSubtreeDefinitions($module);

    foreach $d (@$idl) {

	if ($d->{TYPE} eq "INTERFACE") {
	    foreach $d (@{$d->{DATA}}) {

		# Generate function code fragments

		$res .= EtherealFunction($d), if $d->{TYPE} eq "FUNCTION";

		# Generate structure code fragments

		$res .= EtherealTypedef($module, $d), 
		    if $d->{TYPE} eq "TYPEDEF";
	    }
	}
    }

    $res .= EtherealSubdissectorRegistration($module, \@fns);

    if ($uuid ne "") {
	$res .= EtherealUuidRegistration($module, $uuid, $uuid_version);
	$res .= EtherealModuleRegistration
	    ($module, EtherealFieldInitialisation($module),
	     EtherealSubtreeInitialisation());
    }

    return $res;
}

1;
