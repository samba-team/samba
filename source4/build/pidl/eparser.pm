###################################################
# parser generator for IDL structures
# Copyright tpot@samba.org 2001
# Copyright tridge@samba.org 2000
# released under the GNU GPL

package IdlEParser;

use strict;
use dump;
use Data::Dumper;

my($name);

sub ParamSimpleNdrType($)
{
    my($p) = shift;
    my($res);

    $res .= "\toffset = dissect_ndr_$p->{TYPE}(tvb, offset, pinfo, tree, drep, hf_$p->{NAME}, NULL);\n";

    return $res;
}

sub ParamPolicyHandle($)
{
    my($p) = shift;
    my($res);

    $res .= "\toffset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_policy_hnd, NULL, NULL, FALSE, FALSE);\n";

    return $res;
}

my %param_handlers = (
		      'uint16' => \&ParamSimpleNdrType,
		      'uint32' => \&ParamSimpleNdrType,
		      'policy_handle' => \&ParamPolicyHandle,
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

    $res .= "\t/* Unhandled IDL type '$p->{TYPE}' in $p->{PARENT}->{NAME} */\n";

    return $res;
    # exit(1);
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

    $res .= "\treturn offset;\n";
    $res .= "}\n\n";

    # Response function

    $res .= "static int\n";
    $res .= "$f->{NAME}_resp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)\n";
    $res .= "{\n";

    foreach $d (@{$f->{DATA}}) {
	$res .= ParseParameter($d), if defined($d->{PROPERTIES}{out});
    }

    $res .= "\n";
    $res .= "\treturn offset;\n";
    $res .= "}\n\n";

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
    }

    return $res;
}

#####################################################################
# Pass 1: Stuff required before structs and functions

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

sub Pass1Interface($)
{
    my($interface) = shift;
    my($res) = "";

    $res .= << "EOF";
static int proto_dcerpc_$name = -1;

static int hf_${name}_opnum = -1;
static int hf_${name}_rc = -1;
static int hf_policy_hnd = -1;

static gint ett_dcerpc_$name = -1;

EOF

    my %p = ();

    foreach my $fn (@{$interface->{DATA}}) {
	next, if $fn->{TYPE} ne "FUNCTION";
	foreach my $args ($fn->{DATA}) {
	    foreach my $params (@{$args}) {
		$res .= "static int hf_$params->{NAME} = -1;\n",
   		    if not defined $p{$params->{NAME}};
		$p{$params->{NAME}} = 1;
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

    $res .= << "EOF";
void
proto_reg_handoff_dcerpc_$name(void)
{
        dcerpc_init_uuid(proto_dcerpc_$name, ett_dcerpc_$name, 
			 &uuid_dcerpc_$name, ver_dcerpc_$name, 
			 dcerpc_${name}_dissectors, hf_${name}_opnum);
}
EOF

    return $res;
}

1;
