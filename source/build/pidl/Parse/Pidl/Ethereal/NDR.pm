##################################################
# Samba4 NDR parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# Copyright jelmer@samba.org 2004-2005
# Portions based on idl2eth.c by Ronnie Sahlberg
# released under the GNU GPL

# TODO:
#  - order of functions generated per element level
#  - subcontexts using tvb_new_subset()
#  - fixed arrays
#  - strip prefixes
#  - allow overrides in conformance file

package Parse::Pidl::Ethereal::NDR;

use strict;
use Parse::Pidl::Typelist;
use Parse::Pidl::Util qw(has_property ParseExpr property_matches);
use Parse::Pidl::NDR;
use Parse::Pidl::Dump qw(DumpTypedef DumpFunction);
use Parse::Pidl::Ethereal::Conformance qw(EmitProhibited FindDissectorParam %hf_renames %protocols);

my %types;

my %ptrtype_mappings = (
	"unique" => "NDR_POINTER_UNIQUE",
	"ref" => "NDR_POINTER_REF",
	"ptr" => "NDR_POINTER_PTR"
);

sub type2ft($)
{
    my($t) = shift;
 
    return "FT_UINT$1" if $t =~ /uint(8|16|32|64)/;
    return "FT_INT$1" if $t =~ /int(8|16|32|64)/;
    return "FT_UINT64", if $t eq "HYPER_T" or $t eq "NTTIME"
	or $t eq "NTTIME_1sec" or $t eq "NTTIME_hyper" or $t eq "hyper";

    return "FT_STRING" if ($t eq "string");
   
    return "FT_NONE";
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

sub PrintIdl($)
{
	my $idl = shift;

	foreach (split /\n/, $idl) {
		pidl_code "/* IDL: $_ */";
	}
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

	my $enum_size = $e->{BASE_TYPE};
	$enum_size =~ s/uint//g;
	register_type($name, "offset=$dissectorname(tvb,offset,pinfo,tree,drep,\@HF\@,\@PARAM\@);", type2ft($e->{BASE_TYPE}), "BASE_DEC", "0", "VALS($valsstring)", $enum_size / 8);
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
		
	pidl_code "g$e->{BASE_TYPE} flags;";
	if ($e->{ALIGN} > 1) {
		pidl_code "ALIGN_TO_$e->{ALIGN}_BYTES;";
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
		next unless (/([^ ]*) (.*)/);
		my ($en,$ev) = ($1,$2);
		my $hf_bitname = "hf_$ifname\_$name\_$en";
		my $filtername = "$ifname\.$name\.$en";
		
		register_hf_field($hf_bitname, field2name($en), $filtername, "FT_BOOLEAN", $e->{ALIGN} * 8, "TFS(&$name\_$en\_tfs)", $ev, "");

		pidl_def "static const true_false_string $name\_$en\_tfs = {";
		pidl_def "   \"$en is SET\",";
		pidl_def "   \"$en is NOT SET\",";
		pidl_def "};";
		
		pidl_code "proto_tree_add_boolean(tree, $hf_bitname, tvb, offset-$e->{ALIGN}, $e->{ALIGN}, flags);";
		pidl_code "if (flags&$ev){";
		pidl_code "\tproto_item_append_text(item,\"$en \");";
		pidl_code "}";
		pidl_code "flags&=(~$ev);";
		pidl_code "";
	}

	pidl_code "if(flags){";
	pidl_code "\tproto_item_append_text(item, \"UNKNOWN-FLAGS\");";
	pidl_code "}\n";
	pidl_code "return offset;";
	deindent;
	pidl_code "}\n";

	my $size = $e->{BASE_TYPE};
	$size =~ s/uint//g;
	register_type($name, "offset=$dissectorname(tvb,offset,pinfo,tree,drep,\@HF\@,\@PARAM\@);", type2ft($e->{BASE_TYPE}), "BASE_DEC", "0", "NULL", $size/8);
}

sub ElementLevel($$$$$)
{
	my ($e,$l,$hf,$myname,$pn) = @_;

	if ($l->{TYPE} eq "POINTER") {
		my $type;
		if ($l->{LEVEL} eq "TOP") {
			$type = "toplevel";
		} elsif ($l->{LEVEL} eq "EMBEDDED") {
			$type = "embedded";
		}
		pidl_code "offset=dissect_ndr_$type\_pointer(tvb,offset,pinfo,tree,drep,$myname\_,$ptrtype_mappings{$l->{POINTER_TYPE}},\"".field2name($e->{NAME}) . " ($e->{TYPE})\",$hf);";
	} elsif ($l->{TYPE} eq "ARRAY") {
		my $af = "";

		($af = "ucarray") if ($l->{IS_CONFORMANT});
		($af = "uvarray") if ($l->{IS_VARYING});
		($af = "ucvarray") if ($l->{IS_CONFORMANT} and $l->{IS_VARYING});

		pidl_code "offset=dissect_ndr_$af(tvb,offset,pinfo,tree,drep,$myname\_);";
	} elsif ($l->{TYPE} eq "DATA") {
		if ($l->{DATA_TYPE} eq "string") {
			my $bs = 2;

			if (property_matches($e, "flag", ".*LIBNDR_FLAG_STR_ASCII.*")) {
				$bs = 1;
			}
			
			if (property_matches($e, "flag", ".*LIBNDR_FLAG_STR_SIZE4.*") and property_matches($e, "flag", ".*LIBNDR_FLAG_STR_LEN4.*")) {
				pidl_code "offset=dissect_ndr_cvstring(tvb,offset,pinfo,tree,drep,$bs,$hf,FALSE,NULL);";
			} elsif (property_matches($e, "flag", ".*LIBNDR_FLAG_LEN4.*")) {
				pidl_code "offset=dissect_ndr_vstring(tvb,offset,pinfo,tree,drep,$bs,$hf,FALSE,NULL);";
			}
		} elsif (defined($types{$l->{DATA_TYPE}})) {
			my $param = FindDissectorParam($myname);
			my $x = $types{$l->{DATA_TYPE}}->{CALL};
			$x =~ s/\@HF\@/$hf/g;
			$x =~ s/\@PARAM\@/$param/g;
			pidl_code "$x";
		} else {
			warn("Unknown data type `$l->{DATA_TYPE}'");
		}
	} elsif ($_->{TYPE} eq "SUBCONTEXT") {
		die("subcontext() not supported")
	}
}

sub Element($$$)
{
	my ($e,$pn,$ifname) = @_;

	my $dissectorname = "$ifname\_dissect\_$ifname\_$pn\_$e->{NAME}";

	return if (EmitProhibited($dissectorname));

	my $hf = register_hf_field("hf_$ifname\_$pn\_$e->{NAME}", field2name($e->{NAME}), "$ifname.$pn.$e->{NAME}", type2ft($e->{TYPE}), "BASE_HEX", "NULL", 0, "");
	my $add = "";


	foreach (@{$e->{LEVELS}}) {
		next if ($_->{TYPE} eq "SWITCH");
		pidl_def "static int $dissectorname$add(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);";
		pidl_code "static int";
		pidl_code "$dissectorname$add(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)";
		pidl_code "{";
		indent;

		ElementLevel($e,$_,$hf,$dissectorname.$add,$pn);

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
	
	PrintIdl DumpFunction($fn->{ORIGINAL});
	pidl_code "static int";
	pidl_code "$ifname\_dissect\_$fn->{NAME}_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)";
	pidl_code "{";
	indent;
	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/out/,@{$_->{DIRECTION}})) {
			pidl_code "$dissectornames{$_->{NAME}}";
			pidl_code "offset=dissect_deferred_pointers(pinfo,tvb,offset,drep);";
			pidl_code "";
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
		if (grep(/in/,@{$_->{DIRECTION}})) {
			pidl_code "$dissectornames{$_->{NAME}}";
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
	($res.="\t".Element($_, $name, $ifname)."\n\n") foreach (@{$e->{ELEMENTS}});

	pidl_hdr "int $dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_);";

	pidl_code "int";
	pidl_code "$dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)";
	pidl_code "{";
	indent;
	pidl_code "proto_item *item = NULL;";
	pidl_code "proto_tree *tree = NULL;";
	pidl_code "int old_offset;";
	pidl_code "";

	if ($e->{ALIGN} > 1) {
		pidl_code "ALIGN_TO_$e->{ALIGN}_BYTES;";
	}
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

	pidl_code "proto_item_set_len(item, offset-old_offset);";
	pidl_code "return offset;";
	deindent;
	pidl_code "}\n";

	register_type($name, "offset=$dissectorname(tvb,offset,pinfo,tree,drep,\@HF\@,\@PARAM\@);", "FT_NONE", "BASE_NONE", 0, "NULL", 0);
}

sub Union($$$)
{
	my ($e,$name,$ifname) = @_;

	my $dissectorname = "$ifname\_dissect_$name";
	
	register_ett("ett_$ifname\_$name");

	my $res = "";
	foreach (@{$e->{ELEMENTS}}) {
		$res.="\t\t\t$_->{CASE}:\n";
		if ($_->{TYPE} ne "EMPTY") {
			$res.="\t\t\t\t".Element($_, $name, $ifname)."\n";
		}
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

	if ($e->{ALIGN} > 1) {
		pidl_code "ALIGN_TO_$e->{ALIGN}_BYTES;";
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

	register_type($name, "offset=$dissectorname(tvb,offset,pinfo,tree,drep,\@HF\@,\@PARAM\@);", "FT_NONE", "BASE_NONE", 0, "NULL", 0);
}

sub Typedef($$)
{
	my ($e,$ifname) = @_;

	PrintIdl DumpTypedef($e->{ORIGINAL});

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
	    my $short_name = $x->{NAME};
	    my $filter_name = $x->{NAME};

	    if (has_property($x, "helpstring")) {
	    	$name = $x->{PROPERTIES}->{helpstring};
	    }

	    if (defined($protocols{$x->{NAME}})) {
		$short_name = $protocols{$x->{NAME}}->{SHORTNAME};
		$name = $protocols{$x->{NAME}}->{LONGNAME};
		$filter_name = $protocols{$x->{NAME}}->{FILTERNAME};
	    }

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

	my $define = "__PACKET_DCERPC_" . uc($_->{NAME}) . "_H";
	pidl_hdr "#ifndef $define";
	pidl_hdr "#define $define";
	pidl_hdr "";

	if (defined $x->{PROPERTIES}->{depends}) {
		foreach (split / /, $x->{PROPERTIES}->{depends}) {
			pidl_hdr "#include \"packet-dcerpc-$_\.h\"\n";
		}
	}

	pidl_def "static gint proto_dcerpc_$x->{NAME} = -1;";
	register_ett("ett_dcerpc_$x->{NAME}");
	register_hf_field("hf_$x->{NAME}_opnum", "Operation", "$x->{NAME}.opnum", "FT_UINT16", "BASE_DEC", "NULL", 0, "");

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
	
	    my $maj = $x->{VERSION};
	    $maj =~ s/\.(.*)$//g;
	    pidl_def "static guint16 ver_dcerpc_$x->{NAME} = $maj;";
	    pidl_def "";
	}

	Interface($x);

	pidl_code "\n".DumpFunctionTable($x);

	RegisterInterface($x);
	RegisterInterfaceHandoff($x);

	pidl_hdr "#endif /* $define */";
}


sub register_type($$$$$$$)
{
	my ($type,$call,$ft,$base,$mask,$vals,$length) = @_;

	$types{$type} = {
		TYPE => $type,
		CALL => $call,
		FT_TYPE => $ft,
		BASE => $base,
		MASK => $mask,
		VALSSTRING => $vals,
		LENGTH => $length
	};
}

# Loads the default types
sub Initialize()
{
	foreach my $bytes (qw(1 2 4 8)) {
		my $bits = $bytes * 8;
		register_type("uint$bits", "offset=dissect_ndr_uint$bits(tvb,offset,pinfo,tree,drep,\@HF\@,NULL);", "FT_UINT$bits", "BASE_DEC", 0, "NULL", $bytes);
		register_type("int$bits", "offset=dissect_ndr_int$bits(tvb,offset,pinfo,tree,drep,\@HF\@,NULL);", "FT_INT$bits", "BASE_DEC", 0, "NULL", $bytes);
	}
		
	register_type("udlong", "offset=dissect_ndr_duint32(tvb,offset,pinfo,tree,drep,\@HF\@,NULL);", "FT_UINT64", "BASE_DEC", 0, "NULL", 4);
	register_type("bool8", "offset=dissect_ndr_uint8(tvb,offset,pinfo,tree,drep,\@HF\@,NULL);","FT_INT8", "BASE_DEC", 0, "NULL", 1);
	register_type("char", "offset=dissect_ndr_int8(tvb,offset,pinfo,tree,drep,\@HF\@,NULL);","FT_INT8", "BASE_DEC", 0, "NULL", 1);
	register_type("long", "offset=dissect_ndr_int32(tvb,offset,pinfo,tree,drep,\@HF\@,NULL);","FT_INT32", "BASE_DEC", 0, "NULL", 4);
	register_type("dlong", "offset=dissect_ndr_duint32(tvb,offset,pinfo,tree,drep,\@HF\@,NULL);","FT_INT64", "BASE_DEC", 0, "NULL", 8);
	register_type("GUID", "offset=dissect_ndr_uuid_t(tvb,offset,pinfo,tree,drep,\@HF\@,NULL);","FT_GUID", "BASE_NONE", 0, "NULL", 4);
	register_type("policy_handle", "offset=dissect_nt_policy_hnd(tvb,offset,pinfo,tree,drep,\@HF\@,NULL,NULL,\@PARAM\@&0x01,\@PARAM\@&0x02);","FT_BYTES", "BASE_NONE", 0, "NULL", 4);
	register_type("NTTIME", "offset=dissect_ndr_nt_NTTIME(tvb,offset,pinfo,tree,drep,\@HF\@);","FT_ABSOLUTE_TIME", "BASE_NONE", 0, "NULL", 4);
	register_type("NTTIME_hyper", "offset=dissect_ndr_nt_NTTIME(tvb,offset,pinfo,tree,drep,\@HF\@);","FT_ABSOLUTE_TIME", "BASE_NONE", 0, "NULL", 4);
	register_type("time_t", "offset=dissect_ndr_time_t(tvb,offset,pinfo,tree,drep,\@HF\@,NULL);","FT_ABSOLUTE_TIME", "BASE_DEC", 0, "NULL", 4);
	register_type("NTTIME_1sec", "offset=dissect_ndr_nt_NTTIME(tvb,offset,pinfo,tree,drep,\@HF\@);", "FT_ABSOLUTE_TIME", "BASE_NONE", 0, "NULL", 4);
	register_type("SID", "
		dcerpc_info *di = (dcerpc_info *)pinfo->private_data;

		di->hf_index = \@HF\@;

		offset=dissect_ndr_nt_SID_with_options(tvb,offset,pinfo,tree,drep,param);
	","FT_STRING", "BASE_DEC", 0, "NULL", 4);
	register_type("WERROR", 
		"offset=dissect_ndr_uint32(tvb,offset,pinfo,tree,drep,\@HF\@,NULL);","FT_UINT32", "BASE_DEC", 0, "VALS(NT_errors)", 4);

}

#####################################################################
# Generate ethereal parser and header code
sub Parse($$$)
{
	my($ndr,$module,$filename) = @_;

	Initialize();

	$tabs = "";
	my $h_filename = $filename;

	if ($h_filename =~ /(.*)\.c/) {
		$h_filename = "$1.h";
	}

	%res = (code=>"",def=>"",hdr=>"");

	pidl_hdr "/* header auto-generated by pidl */";

	$res{headers} = "\n";
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

	my $header = "/* autogenerated by pidl */\n\n";
	$header.=$res{hdr};
    
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
		$res.= "\t{ $_->{OPNUM}, \"$_->{NAME}\",\n";
		$res.= "\t   $if->{NAME}_dissect_$_->{NAME}_request, $if->{NAME}_dissect_$_->{NAME}_response},\n";
	}

	$res .= "\t{ 0, NULL, NULL, NULL }\n";

	return "$res};\n";
}


1;
