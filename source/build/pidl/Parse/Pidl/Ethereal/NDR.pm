##################################################
# Samba4 NDR parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# Copyright jelmer@samba.org 2004-2005
# Portions based on idl2eth.c by Ronnie Sahlberg
# released under the GNU GPL

package Parse::Pidl::Ethereal::NDR;

use strict;
use Parse::Pidl::Typelist;
use Parse::Pidl::Util qw(has_property ParseExpr);
use Parse::Pidl::NDR;
use Parse::Pidl::Ethereal::Conformance qw(EmitProhibited FindDissectorParam %hf_renames);

my %ptrtype_mappings = (
	"unique" => "NDR_POINTER_UNIQUE",
	"ref" => "NDR_POINTER_REF",
	"ptr" => "NDR_POINTER_PTR"
);

my %dissectors = (
	"uint16" => "dissect_ndr_uint16",
	"uint8" => "dissect_ndr_uint8",
	"uint32" => "dissect_ndr_uint32",
	"time_t" => "dissect_ndr_time_t",
	"GUID" => "dissect_ndr_uuid_t"
);

sub type2ft($)
{
    my($t) = shift;
 
    return "FT_UINT$1" if $t =~ /uint(8|16|32|64)/;
    return "FT_INT$1" if $t =~ /int(8|16|32|64)/;
    return "FT_UINT64", if $t eq "HYPER_T" or $t eq "NTTIME"
	or $t eq "NTTIME_1sec" or $t eq "NTTIME_hyper" or $t eq "hyper";
   
    return "FT_NONE";
}

# Determine the display base for an element

sub elementbase($)
{
    my($e) = shift;

    if (my $base = has_property($e, "display")) {
	return "BASE_" . uc($base);
    }
 
    return "BASE_DEC", if $e->{TYPE} eq "ENUM";
    return "BASE_DEC", if $e->{TYPE} =~ /u?int(8|16|32|64)/;
    return "BASE_DEC", if $e->{TYPE} eq "NTTIME" or $e->{TYPE} eq "HYPER_T";

    # Probably an enum

    return "BASE_DEC";
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

sub bitmapbase($)
{
    my $e = shift;

    return "16", if has_property($e->{DATA}, "bitmap16bit");
    return "8", if has_property($e->{DATA}, "bitmap8bit");

    return "32";
}

my %res = ();
my $tabs = "";
sub pidl_code($)
{
	my $d = shift;
	if ($d) {
		$res{code} .= $tabs;
		$res{code} .= $d;
	}
	$res{code} .="\n";
}

sub pidl_hdr($) { my $x = shift; $res{hdr} .= "$x\n"; }
sub pidl_def($) { my $x = shift; $res{def} .= "$x\n"; }

sub indent()
{
	$tabs .= "\t";
}

sub deindent()
{
	$tabs = substr($tabs, 0, -1);
}

#####################################################################
# parse the interface definitions
sub Interface($)
{
	my($interface) = @_;
	Typedef($_,$interface->{NAME}) foreach (@{$interface->{TYPEDEFS}});
	Function($_,$interface->{NAME}) foreach (@{$interface->{FUNCTIONS}});
}

sub Enum($$$)
{
	my ($e,$name,$ifname) = @_;
	my $valsstring = "$ifname\_$name\_vals";
	my $dissectorname = "$ifname\_dissect\_$name";

    	foreach (@{$e->{ELEMENTS}}) {
		if (/([^=]*)=(.*)/) {
			pidl_hdr "#define $1 $2";
		}
	}
	
	pidl_hdr "extern const value_string $valsstring;";
	pidl_hdr "int $dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param);";

	pidl_def "const value_string ".$valsstring."[] = {";
	indent;
    	foreach (@{$e->{ELEMENTS}}) {
		next unless (/([^=]*)=(.*)/);
		pidl_code "{ $1, \"$2\" },";
	}

	pidl_def "{ 0, NULL }";
	deindent;
	pidl_def "};";

	pidl_code "int";
	pidl_code "$dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param _U_)";
	pidl_code "{";
	indent;
	pidl_code "offset=dissect_ndr_$e->{BASE_TYPE}(tvb, offset, pinfo, tree, drep, hf_index, NULL);";
	pidl_code "return offset;";
	pidl_code "}\n";

	register_hf_field($name, $dissectorname, enum_ft($e), "BASE_DEC", "0", "VALS($valsstring)", enum_size($e));
}

sub Bitmap($$$)
{
	my ($e,$name,$ifname) = @_;
	my $dissectorname = "$ifname\_dissect\_$name";

	register_ett("ett_$ifname\_$name");

	pidl_hdr "int $dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param);";

	pidl_code "int";
	pidl_code "$dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)";
	pidl_code "{";
	indent;
	pidl_code "proto_item *item=NULL;";
	pidl_code "proto_tree *tree=NULL;";
	pidl_code "";

	if ($e->{ALIGN} == 8) {
		pidl_code "guint8 flags;";
	} elsif ($e->{ALIGN} == 4) {
		pidl_code "guint32 flags;";
		pidl_code "ALIGN_TO_4_BYTES;";
	}

	pidl_code "";

	pidl_code "if(parent_tree) {";
	indent;
	pidl_code "item=proto_tree_add_item(parent_tree, hf_index, tvb, offset, $e->{ALIGN}, TRUE);";
	pidl_code "tree=proto_item_add_subtree(item,ett_$ifname\_$name);";
	deindent;
	pidl_code "}\n";

	pidl_code "offset=dissect_ndr_$e->{BASE_TYPE}(tvb, offset, pinfo, NULL, drep, -1, &flags);";

	foreach (@{$e->{ELEMENTS}}) {
		next unless (/([^=]*)=(.*)/);
		my ($en,$ev) = ($1,$2);
		my $hf_bitname = "hf_$ifname\_$name\_$en";
		my $filtername = "$ifname\.$name\.$en";
		
		register_hf_field($hf_bitname, $en, $filtername, "FT_BOOLEAN", $e->{ALIGN} * 8, "TFS(&$en\_tfs)", $ev, "");

		pidl_def "static const true_false_string $name\_tfs = {";
		pidl_def "   \"$name is SET\",";
		pidl_def "   \"$name is NOT SET\",";
		pidl_def "};";
		
		pidl_code "proto_tree_add_boolean(tree, $hf_bitname, tvb, offset-$e->{ALIGN}, $e->{ALIGN}, flags);";
		pidl_code "if (flags&$ev){";
		pidl_code "\tproto_item_append_text(item,\"$en\");";
		pidl_code "}\n";
		pidl_code "flags&=(~$ev);";
	}

	pidl_code "if(flags){";
	pidl_code "proto_item_append_text(item, \"UNKNOWN-FLAGS\");";
	pidl_code "}\n";
	deindent;
	pidl_code "return offset;";
	pidl_code "}\n";
}

sub ElementLevel($$$$)
{
	my ($e,$l,$hf,$myname) = @_;

	if ($l->{TYPE} eq "POINTER") {
		my $type;
		if ($l->{LEVEL} eq "TOP") {
			$type = "toplevel";
		} elsif ($l->{LEVEL} eq "EMBEDDED") {
			$type = "embedded";
		}
		pidl_code "offset=dissect_ndr_$type\_pointer(tvb,offset,pinfo,tree,drep,$myname\_,$ptrtype_mappings{$l->{POINTER_TYPE}},\"\",$hf);";
	} elsif ($l->{TYPE} eq "ARRAY") {
		my $af = "";

		($af = "ucarray") if ($l->{IS_VARYING});
		($af = "uvarray") if ($l->{IS_CONFORMANT});
		($af = "ucvarray") if ($l->{IS_CONFORMANT} and $l->{IS_VARYING});

		pidl_code "offset=dissect_ndr_$af(tvb,offset,pinfo,tree,drep,$myname\_);";
	} elsif ($l->{TYPE} eq "DATA") {
		pidl_code "guint32 param="  . FindDissectorParam($myname).";";
		defined($dissectors{$l->{DATA_TYPE}}) or warn("Unknown data type $l->{DATA_TYPE}");
		pidl_code "offset=".$dissectors{$l->{DATA_TYPE}}."(tvb, offset, pinfo, tree, drep, $hf, param);";
	} elsif ($_->{TYPE} eq "SUBCONTEXT") {
		die("subcontext() not supported")
	}
}

sub Element($$$)
{
	my ($e,$pn,$ifname) = @_;

	my $dissectorname = "$ifname\_dissect\_$ifname\_$pn\_$e->{NAME}";

	return if (EmitProhibited($dissectorname));

	my $hf = register_hf_field("hf_$ifname\_$pn\_$e->{NAME}", $e->{NAME}, "$ifname.$pn.$e->{NAME}", type2ft($e->{TYPE}), "BASE_HEX", "NULL", 0, "");
	my $add = "";

	foreach (@{$e->{LEVELS}}) {
		next if ($_->{TYPE} eq "SWITCH");
		pidl_code "static int";
		pidl_code "$dissectorname$add(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)";
		pidl_code "{";
		indent;

		ElementLevel($e,$_,$hf,$dissectorname.$add);

		pidl_code "return offset;";
		deindent;
		pidl_code "}\n";
		$add.="_";
	}

	return "offset=$dissectorname(tvb,offset,pinfo,tree,drep);";
}

sub Function($$$)
{
	my ($fn,$ifname) = @_;

	my %dissectornames;

	foreach (@{$fn->{ELEMENTS}}) {
		$dissectornames{$_->{NAME}} = Element($_, $fn->{NAME}, $ifname) 
	}
	
	pidl_code "static int";
	pidl_code "$ifname\_dissect\_$fn->{NAME}_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)";
	pidl_code "{";
	indent;
	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/in/,@{$_->{DIRECTION}})) {
			pidl_code "dissectornames{$_->{NAME}};";
			pidl_code "offset=dissect_deferred_pointers(pinfo,tvb,offset,drep);";
		}
	}
	pidl_code "return offset;";
	deindent;
	pidl_code "}\n";

	pidl_code "static int";
	pidl_code "$ifname\_dissect\_$fn->{NAME}_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)";
	pidl_code "{";
	indent;
	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/out/,@{$_->{DIRECTION}})) {
			pidl_code "$dissectornames{$_->{NAME}};";
			pidl_code "offset=dissect_deferred_pointers(pinfo,tvb,offset,drep);";
		}

	}
	pidl_code "return offset;";
	deindent;
	pidl_code "}\n";
}

sub Struct($$$)
{
	my ($e,$name,$ifname) = @_;
	my $dissectorname = "$ifname\_dissect\_$name";

	return if (EmitProhibited($dissectorname));

	register_ett("ett_$ifname\_$name");

	my $res = "";
	($res.="\t".Element($_, $name, $ifname)."\n") foreach (@{$e->{ELEMENTS}});

	pidl_hdr "int $dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_);";

	pidl_code "int";
	pidl_code "$dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)";
	pidl_code "{";
	indent;
	pidl_code "proto_item *item = NULL;";
	pidl_code "proto_tree *tree = NULL;";
	pidl_code "int old_offset;";
	pidl_code "";

	pidl_code "ALIGN_TO_$e->{ALIGN}_BYTES;";
	pidl_code "";

	pidl_code "old_offset=offset;";
	pidl_code "";
	pidl_code "if(parent_tree){";
	indent;
	pidl_code "item=proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);";
	pidl_code "tree=proto_item_add_subtree(item, ett_$ifname\_$name);";
	deindent;
	pidl_code "}";

	pidl_code "\n$res";


	pidl_code "";
	pidl_code "proto_item_set_len(item, offset-old_offset);";
	pidl_code "return offset;";
	deindent;
	pidl_code "}\n";
}

sub Union($$$)
{
	my ($e,$name,$ifname) = @_;

	my $dissectorname = "$ifname\_dissect_$name";
	
	register_ett("ett_$ifname\_$name");

	my $res = "";
	foreach (@{$e->{ELEMENTS}}) {
		$res.="\t\t\t$_->{CASE}:\n";
		$res.="\t\t\t\t".Element($_, $name, $ifname)."\n";
		$res.="\t\t\tbreak;\n\n";
	}

	pidl_code "static int";
	pidl_code "$dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)";
	pidl_code "{";
	indent;
	pidl_code "proto_item *item=NULL;";
	pidl_code "proto_tree *tree=NULL;";
	pidl_code "int old_offset;";
	pidl_code "g$e->{SWITCH_TYPE} level;";
	pidl_code "";

	if ($e->{ALIGN} == 2) {
		pidl_code "ALIGN_TO_2_BYTES;";
	} elsif ($e->{ALIGN} == 4) {
		pidl_code "ALIGN_TO_4_BYTES;";
	}


	pidl_code "";

	pidl_code "old_offset=offset;";
	pidl_code "if(parent_tree){";
	indent;
	pidl_code "item=proto_tree_add_text(parent_tree,tvb,offset,-1,\"$name\");";
	pidl_code "tree=proto_item_add_subtree(item,ett_$ifname\_$name);";
	pidl_code "}";

	pidl_code "";

	pidl_code "offset = dissect_ndr_$e->{SWITCH_TYPE}(tvb, offset, pinfo, tree, drep, hf_index, &level);";

	pidl_code "switch(level) {";
	pidl_code $res;
	pidl_code "proto_item_set_len(item, offset-old_offset);";
	pidl_code "return offset;";
	deindent;
	pidl_code "}";

}

sub Typedef($$)
{
	my ($e,$ifname) = @_;

	{
		ENUM => \&Enum,
		STRUCT => \&Struct,
		UNION => \&Union,
		BITMAP => \&Bitmap
	}->{$e->{DATA}->{TYPE}}->($e->{DATA}, $e->{NAME}, $ifname);
}

sub RegisterInterface($)
{
	my ($x) = @_;

	pidl_code "void proto_register_dcerpc_$x->{NAME}(void)";
	pidl_code "{";
	indent;

	$res{code}.=DumpHfList()."\n";
	$res{code}.="\n".DumpEttList()."\n";
	
	if (defined($x->{UUID})) {
	    # These can be changed to non-pidl_code names if the old dissectors
	    # in epan/dissctors are deleted.
    
	    my $name = "\"" . uc($x->{NAME}) . " (pidl)\"";
		if (has_property($x, "helpstring")) {
			$name = $x->{PROPERTIES}->{helpstring};
		}
	    my $short_name = "idl_$x->{NAME}";
	    my $filter_name = "idl_$x->{NAME}";
    
	    pidl_code "proto_dcerpc_$x->{NAME} = proto_register_protocol($name, \"$short_name\", \"$filter_name\");";
	    
	    pidl_code "proto_register_field_array(proto_dcerpc_$x->{NAME}, hf, array_length (hf));";
	    pidl_code "proto_register_subtree_array(ett, array_length(ett));";
	} else {
	    pidl_code "proto_dcerpc = proto_get_id_by_filter_name(\"dcerpc\");";
	    pidl_code "proto_register_field_array(proto_dcerpc, hf, array_length(hf));";
	    pidl_code "proto_register_subtree_array(ett, array_length(ett));";
	}
	    
	deindent;
	pidl_code "}\n";
}

sub RegisterInterfaceHandoff($)
{
	my $x = shift;
	pidl_code "void proto_reg_handoff_dcerpc_$x->{NAME}(void)";
	pidl_code "{";
	indent;
	pidl_code "dcerpc_init_uuid(proto_dcerpc_$x->{NAME}, ett_dcerpc_$x->{NAME},";
	pidl_code "\t&uuid_dcerpc_$x->{NAME}, ver_dcerpc_$x->{NAME},";
	pidl_code "\t$x->{NAME}_dissectors, hf_$x->{NAME}_opnum);";
	deindent;
	pidl_code "}";
}

sub ProcessInterface($)
{
	my $x = shift;

	foreach (@{$x->{TYPEDEFS}}) {
		$dissectors{$_->{NAME}} = "$x->{NAME}_dissect_$_->{NAME}";
	}

	if (defined($x->{UUID})) {
		my $if_uuid = $x->{UUID};

	    pidl_def "/* Version information */\n\n";
	    
	    pidl_def "static e_uuid_t uuid_dcerpc_$x->{NAME} = {";
	    pidl_def "\t0x" . substr($if_uuid, 1, 8) 
  		. ", 0x" . substr($if_uuid, 10, 4)
	    . ", 0x" . substr($if_uuid, 15, 4) . ",";
	    pidl_def "\t{ 0x" . substr($if_uuid, 20, 2) 
		. ", 0x" . substr($if_uuid, 22, 2)
	    . ", 0x" . substr($if_uuid, 25, 2)
	    . ", 0x" . substr($if_uuid, 27, 2)
	    . ", 0x" . substr($if_uuid, 29, 2)
	    . ", 0x" . substr($if_uuid, 31, 2)
	    . ", 0x" . substr($if_uuid, 33, 2)
	    . ", 0x" . substr($if_uuid, 35, 2) . " }";
	    pidl_def "};";
	
	    pidl_def "static guint16 ver_dcerpc_$x->{NAME} = $x->{VERSION};";
	    pidl_def "";
	}

	Interface($x);

	$res{functiontable} = DumpFunctionTable($x);

	RegisterInterface($x);
	RegisterInterfaceHandoff($x);
}

#####################################################################
# Generate ethereal parser and header code
sub Parse($$$)
{
	my($ndr,$module,$filename) = @_;

	$tabs = "";
	my $h_filename = $filename;

	if ($h_filename =~ /(.*)\.c/) {
		$h_filename = "$1.h";
	}

	%res = (code=>"",def=>"",hdr=>"");

	pidl_hdr "/* header auto-generated by pidl */";

	$res{headers} = "";
	$res{headers} .= "#ifdef HAVE_CONFIG_H\n";
	$res{headers} .= "#include \"config.h\"\n";
	$res{headers} .= "#endif\n\n";
	$res{headers} .= "#include <glib.h>\n";
	$res{headers} .= "#include <string.h>\n";
	$res{headers} .= "#include <epan/packet.h>\n\n";

	$res{headers} .= "#include \"packet-dcerpc.h\"\n";
	$res{headers} .= "#include \"packet-dcerpc-nt.h\"\n";
	$res{headers} .= "#include \"packet-windows-common.h\"\n";
	$res{headers} .= "#include \"$h_filename\"\n";
	pidl_code "";

	# Ethereal protocol registration

	ProcessInterface($_) foreach (@$ndr);

	$res{ett} = DumpEttDeclaration();
	$res{hf} = DumpHfDeclaration();

	my $parser = "/* parser auto-generated by pidl */";
	$parser.= $res{headers};
	$parser.=$res{ett};
	$parser.=$res{hf};
	$parser.=$res{def};
	$parser.=$res{code};

	my $define = "__PACKET_DCERPC_" . uc($_->{NAME}) . "_H";
	my $header = "#ifndef $define\n#define $define\n\n".$res{hdr} . "\n#endif /* $define */\n";
    
	return ($parser,$header);
}

###############################################################################
# ETT
###############################################################################

my @ett = ();

sub register_ett($)
{
	my $name = shift;

	push (@ett, $name);	
}

sub DumpEttList()
{
	my $res = "\tstatic gint *ett[] = {\n";
	foreach (@ett) {
		$res .= "\t\t&$_,\n";
	}

	return "$res\t};\n";
}

sub DumpEttDeclaration()
{
	my $res = "\n/* Ett declarations */\n";
	foreach (@ett) {
		$res .= "static gint $_ = -1;\n";
	}

	return "$res\n";
}

###############################################################################
# HF
###############################################################################

my %hf = ();

sub register_hf_field($$$$$$$$) 
{
	my ($index,$name,$filter_name,$ft_type,$base_type,$valsstring,$mask,$blurb) = @_;

	return $hf_renames{$index} if defined ($hf_renames{$index});

	$hf{$index} = {
		INDEX => $index,
		NAME => $name,
		FILTER => $filter_name,
		FT_TYPE => $ft_type,
		BASE_TYPE => $base_type,
		VALS => $valsstring,
		MASK => $mask,
		BLURB => $blurb
	};

	return $index;
}

sub DumpHfDeclaration()
{
	my $res = "";

	$res = "\n/* Header field declarations */\n";

	foreach (keys %hf) 
	{
		$res .= "static gint $_ = -1;\n";
	}

	return "$res\n";
}

sub DumpHfList()
{
	my $res = "\tstatic hf_register_info hf[] = {\n";

	foreach (values %hf) 
	{
		$res .= "\t{ &$_->{INDEX}, 
	  { \"$_->{NAME}\", \"$_->{FILTER}\", $_->{FT_TYPE}, $_->{BASE_TYPE}, $_->{VALS}, $_->{MASK}, \"$_->{BLURB}\", HFILL }},
";
	}

	return $res."\t};\n";
}


###############################################################################
# Function table
###############################################################################

sub DumpFunctionTable($)
{
	my $if = shift;

	my $res = "static dcerpc_sub_dissector $if->{NAME}\_dissectors[] = {\n";
	
	foreach (@{$if->{FUNCTIONS}}) {
		$res.= "\t{ $_->{OPNUM}, \"$_->{NAME},\n";
		$res.= "\t   $if->{NAME}_dissect_$_->{NAME}_request, $if->{NAME}_dissect_$_->{NAME}_response},\n";
	}

	$res .= "\t{ 0, NULL, NULL, NULL },\n";

	return "$res\t}\n";
}


1;
