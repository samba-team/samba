###################################################
# Samba4 parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001,2004-2005
# released under the GNU GPL

package IdlEParser;

use ndr;
use strict;

# the list of needed functions
my %needed;
my %bitmaps;

my $module;
my $if_uuid;
my $if_version;
my $if_endpoints;

sub pidl($)
{
	print OUT shift;
}

#####################################################################
# a list of annotations 

my $nopull_typedefs = {
#    "policy_handle" => "1",
};

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
	pidl "\tstruct $fn->{NAME} *r = talloc(NULL, struct $fn->{NAME});\n";
	pidl "\tpidl_tree ptree;\n\n";

	pidl "\tptree.proto_tree = tree;\n";
	pidl "\tptree.subtree_list = NULL;\n\n";

	pidl "\tndr_pull_$fn->{NAME}(ndr, NDR_IN, &ptree, r);\n";

	pidl "\n\treturn ndr->offset;\n";
	pidl "}\n\n";

	# response function
	pidl "int $fn->{NAME}_resp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)\n{\n";

	pidl "\tstruct pidl_pull *ndr = pidl_pull_init(tvb, offset, pinfo, drep);\n";
	pidl "\tstruct $fn->{NAME} *r = talloc(NULL, struct $fn->{NAME});\n";
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
 
    return "FT_UINT$1" if $t =~ /uint(8|16|32|64)/;
    return "FT_INT$1" if $t =~ /int(8|16|32|64)/;
    return "FT_UINT64", if $t eq "HYPER_T" or $t eq "NTTIME"
	or $t eq "NTTIME_1sec" or $t eq "NTTIME_hyper";
    
    # Type is an enum

    return "FT_UINT16";
}

# Determine the display base for an element

sub elementbase($)
{
    my($e) = shift;

    if (my $base = util::has_property($e, "display")) {
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

sub NeededFunction($)
{
	my $fn = shift;

	$needed{"pull_$fn->{NAME}"} = 1;

	# Add entries for function arguments

	foreach my $e (@{$fn->{ELEMENTS}}) {

		$e->{PARENT} = $fn;
		$needed{"pull_$e->{TYPE}"} = 1;

		if (NdrParser::is_scalar_type($e->{TYPE})) {

		    if (defined($e->{ARRAY_LEN}) or 
			util::has_property($e, "size_is")) {

			# Array of scalar types

			$needed{"hf_$fn->{NAME}_$e->{NAME}_array"} = {
			    'name' => field2name($e->{NAME}),
			    'type' => $e->{TYPE},
			    'ft'   => "FT_BYTES",
			    'base' => elementbase($e)
			    };

		    } else {

			$needed{"hf_$fn->{NAME}_$e->{NAME}"} = {
			'name' => field2name($e->{NAME}),
			'type' => $e->{TYPE},
			'ft'   => type2ft($e->{TYPE}),
			'base' => elementbase($e)
			};

		    }

		    $e->{PARENT} = $fn;

		} else {
		    $needed{"ett_$e->{TYPE}"} = 1;
		}
	}

	# Add entry for return value

	$needed{"hf_$fn->{NAME}_result"} = {
	    'name' => field2name('result'),
	    'type' => $fn->{RETURN_TYPE},
	    'ft' => type2ft($fn->{RETURN_TYPE}),
	    'base' => elementbase($fn)
	};
}

sub bitmapbase($)
{
    my $e = shift;

    return "16", if util::has_property($e->{DATA}, "bitmap16bit");
    return "8", if util::has_property($e->{DATA}, "bitmap8bit");

    return "32";
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

			if (NdrParser::is_scalar_type($e->{TYPE})) {

				if (defined($e->{ARRAY_LEN}) or 
				util::has_property($e, "size_is")) {

					# Arrays of scalar types are FT_BYTES

					$needed{"hf_$t->{NAME}_$e->{NAME}_array"} = {
						'name' => field2name($e->{NAME}),
						'type' => $e->{TYPE},
						'ft'   => "FT_BYTES",
						'base' => elementbase($e)
					};

				} else {

					$needed{"hf_$t->{NAME}_$e->{NAME}"} = {
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
		for my $e (@{$t->{DATA}->{ELEMENTS}}) {

			$e->{PARENT} = $t->{DATA};

			if ($needed{"pull_$t->{NAME}"}) {
				$needed{"pull_$e->{TYPE}"} = 1;
			}

			$needed{"ett_$e->{TYPE}"} = 1;
		}

		$needed{"ett_$t->{NAME}"} = 1;
	}

	if ($t->{DATA}->{TYPE} eq "ENUM") {

		$needed{"hf_$t->{NAME}"} = {
			'name' => field2name($t->{NAME}),
			'ft' => 'FT_UINT16',
			'base' => 'BASE_DEC',
			'strings' => "VALS($t->{NAME}_vals)"
		};
	}

	if ($t->{DATA}->{TYPE} eq "BITMAP") {

		$bitmaps{$t->{NAME}} = $t;

		foreach my $e (@{$t->{DATA}{ELEMENTS}}) {
			$e =~ /^(.*?) \( (.*?) \)$/;
			$needed{"hf_$t->{NAME}_$1"} = {
				'name' => "$1",
				'ft' => "FT_BOOLEAN",
				'base' => bitmapbase($t),
				'bitmask' => "$2"
			};
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
# generate code to parse an enum

sub ParseEnum($)
{
    my ($e) = shift;

    pidl "static const value_string $e->{PARENT}{NAME}_vals[] =\n";
    pidl "{\n";

    foreach my $x (@{$e->{ELEMENTS}}) {
	$x =~ /([^=]*)=(.*)/;
	pidl "\t{ $1, \"$1\" },\n";
    }
    
    pidl "};\n\n";
}

#####################################################################
# rewrite autogenerated header file
sub RewriteHeader($$$)
{
    my($idl) = shift;
    my($input) = shift;
    my($output) = shift;

	NdrParser::Load($idl);

    %needed = ();

    # Open files

    open(IN, "<$input") || die "can't open $input for reading";
    open(OUT, ">$output") || die "can't open $output for writing";    
   
    # Read through file

    while(<IN>) {

	# Not interested in ndr_push or ndr_print routines as they
	# define structures we aren't interested in.

	s/^NTSTATUS ndr_push.*?;\n//smg;
	s/^void ndr_print.*?;\n//smg;

	# Get rid of async send and receive function.

	s/^NTSTATUS dcerpc_.*?;//smg;
	s/^struct rpc_request.*?;//smg;

	# Rewrite librpc includes

	s/^\#include\ \"librpc\/gen_ndr\/ndr_(.*?).h\"$
	    /\#include \"packet-dcerpc-$1.h\"/smgx;

	# Rename struct ndr_pull to struct pidl_pull

	s/struct ndr_pull \*ndr/struct pidl_pull \*ndr/smg;

	# Change prototypes for public functions

	s/(struct pidl_pull \*ndr, int ndr_flags)/$1, pidl_tree *tree/smg;

	# Bitmaps

	s/int ndr_flags, (pidl_tree \*tree), (uint32_t \*r\);)/$1, int hf, $2/smg;

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

	NdrParser::Load($idl);

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

    pidl "\n";

    foreach my $y (keys(%needed)) {
	pidl "static int $y = -1;\n", if $y =~ /^hf_/;
    }

    pidl "\n";

    foreach my $y (keys(%needed)) {
	pidl "static gint $y = -1;\n", if $y =~ /^ett_/;
    }

    pidl "\n";

    # Read through file

    my $cur_fn = "";

    while(<IN>) {

	#
        # Regexps to do a first pass at removing stuff we aren't
	# interested in for ethereal parsers.
	#

	next, if /^\#include \"includes.h\"/;

	# Rewrite includes to packet-dcerpc-foo.h instead of ndr_foo.h

	s/^\#include \".*?ndr_(.*?).h\"$/\#include \"packet-dcerpc-$1.h\"/smg;

	if (/\.h\"$/) {
	    pidl $_;
	    foreach my $x (@{$idl}) {
		if ($x->{TYPE} eq "INTERFACE") { 
		    foreach my $y (@{$x->{INHERITED_DATA}}) {
			if ($y->{TYPE} eq "TYPEDEF") {
			    ParseEnum($y->{DATA}), if $y->{DATA}{TYPE} eq "ENUM";
			}
		    }
		}
	    }
	    next;
	}

	# Remove the NDR_CHECK() macro calls.  Ethereal take care of
	# this for us as part of the tvbuff_t structure.

	s/NDR_CHECK\((.*)\)/$1/g;

	# We're not interested in ndr_{print,push,size} functions so
	# just delete them.

	next, if /^(static )?NTSTATUS ndr_push/ .. /^}/;
        next, if /^void ndr_print/ .. /^}/;
        next, if /^size_t ndr_size/ .. /^}/;

	# get rid of the init functions
	next, if /^NTSTATUS dcerpc_ndr_\w+_init/ .. /^}/;

	# Get rid of dcerpc interface structures and functions since
	# they are also not very interesting.

        next, if /^static const struct dcerpc_interface_call/ .. /^};/;
        next, if /^static const char \* const [a-z]+_endpoint_strings/ ../^};/;
        next, if /^static const struct dcerpc_endpoint_list/ .. /^};/;
        next, if /^const struct dcerpc_interface_table/ .. /^};/;
        next, if /^static NTSTATUS dcerpc_ndr_[a-z]+_init/ .. /^}/;
        next, if /^NTSTATUS dcerpc_[a-z]+_init/ .. /^}/;

        #
        # Remember which structure or function we are processing.
        #

        $cur_fn = $1, if /NTSTATUS ndr_pull_(.*?)\(struct/;

        # Skip functions we have marked as nopull

        my $skip_fn = 0;

        foreach my $f (keys(%{$nopull_typedefs})) {
	    $skip_fn = 1, if $cur_fn eq $f;
	}

        $cur_fn = "", if /^}/;

        next, if $skip_fn;

	#
	# OK start wrapping the ndr_pull functions that actually
	# implement the NDR decoding routines.  This mainly consists
	# of adding a couple of parameters to each function call.
        #

	# Add proto tree and name argument to ndr_pull_unique_ptr() calls.

	s/(ndr_pull_unique_ptr\(ndr,\ (&_ptr_([^\)]*?))\);)
	    /ndr_pull_ptr(ndr, tree, "$3", $2);/smgx;

	# Wrap ndr_pull_array_size() and ndr_pull_array_length()
	# functions.  Add leading space in front of first parameter so
	# we won't get caught by later regexps.

	s/(ndr_pull_array_(size|length)\(ndr,\ ([^\)]*?)\);)
	    /ndr_pull_array_$2( ndr, tree, $3);/smgx;

	# Add tree argument to ndr_pull_array() and
	# ndr_pull_array_foo() calls.

	s/(ndr_pull_array\(
	   ndr,\ 
	   ([^,]*?),\                                # NDR_SCALARS etc
	   (\(void\ \*\*\)r->(in|out|)\.?([^,]*?)),\ # Pointer to array entries
	   ([^\)].*?)\);)                            # All other arguments
	    /ndr_pull_array( ndr, $2, tree, $3, $6);/smgx;

 	s/(ndr_pull_array_([^\(]*?)\(
 	   ndr,\ 
 	   ([^,]*?),\                               # NDR_SCALARS etc
 	   (r->((in|out).)?([^,]*?)),\              # Pointer to array elements
	   (.*?)\);)                                # Number of elements
	    /ndr_pull_array_$2( ndr, $3, tree, hf_${cur_fn}_$7_array, $4, $8);/smgx;
 
	# Save ndr_pull_relative_ptr{1,2}() calls from being wrapped by the
	# proceeding regexp by adding a leading space.

	s/ndr_pull_(relative_ptr1|relative_ptr2)\((.*?)\);/
	    ndr_pull_$1( $2);/smgx;

	# Enums

        s/(^static\ NTSTATUS\ ndr_pull_(.+?),\ int\ ndr_flags,\ (enum\ .+?)\))
	    /static NTSTATUS ndr_pull_$2, pidl_tree *tree, int hf, $3)/smgx;
	s/uint(8|16|32) v;/uint$1_t v;/smg;
	s/(ndr_pull_([^\(]+?)\(ndr,\ NDR_[^,]*,\ &_level\);)
	    /ndr_pull_$2(ndr, tree, hf_${cur_fn}_level, &_level);/smgx;

	# Bitmaps

        s/(^(static\ )?NTSTATUS\ ndr_pull_(.+?),\ int\ ndr_flags,\ uint(8|16|32)_t\ \*r\))
	    /NTSTATUS ndr_pull_$3, pidl_tree *tree, int hf, uint$4_t *r)/smgx;

        if (/ndr_pull_([^\)]*?)\(ndr,\ NDR_[^,]*,\ &v\);/) {

	    s/(ndr_pull_([^\)]*?)\(ndr,\ (NDR_[^,]*?),\ &v\);)
		/ndr_pull_$2(ndr, tree, hf, &v);/smgx;

	    pidl $_;

	    if (defined($bitmaps{$cur_fn})) {
		pidl "\t{\n\t\tproto_tree *subtree = NULL;\n\n";
		pidl "\t\tif (tree->proto_tree)\n\t\t\tsubtree = proto_item_add_subtree(tree->proto_tree->last_child, ett_$cur_fn);\n\n";
		foreach my $e (@{$bitmaps{$cur_fn}->{DATA}{ELEMENTS}}) {
		    $e =~ /^(.*?) \( (.*?) \)$/;
		    pidl "\t\tproto_tree_add_boolean(subtree, hf_${cur_fn}_$1, ndr->tvb, ndr->offset - sizeof(v), sizeof(v), v);\n";
		}
		pidl "\t}\n";
	    }

	    next;
	}

	# Call ethereal wrappers for pull of scalar values in
	# structures and functions, e.g
	#
	# ndr_pull_uint32(ndr, &r->in.access_mask);
	# ndr_pull_uint32(ndr, &r->idx);

        if (/(ndr_pull_([^\)]*?)\(ndr, NDR_[^,]*?, (&?r->((in|out)\.)?([^\)]*?))\);)/ and NdrParser::is_scalar_type($2)) {

	    my $pull_type = "${cur_fn}_$6";

	    if (defined($needed{"hf_$2"})) {
		$pull_type = "$2";
	    }

	    s/(ndr_pull_([^\)]*?)\(
		   ndr,\ 
		   NDR_[^,]*?,\ 
		   (&?r->((in|out)\.)?         # Function args contain leading junk
		([^\)]*?))                 # Element name
	       \);)          
		/ndr_pull_$2(ndr, tree, hf_$pull_type, $3);/smgx;
	}

	# Add tree and hf argument to pulls of "internal" scalars like
	# array sizes, levels, etc.

	s/(ndr_pull_(uint32|uint16)\(
	   ndr,\  
	   NDR_[^,]*?,\ 
	   (&_([^\)]*?))        # Internal arg names have leading underscore
	   \);)
	    /ndr_pull_$2(ndr, tree, hf_$4, $3);/smgx;

	# Add subtree argument to calls dissecting structures/unions, e.g
	#
	# ndr_pull_string(ndr, NDR_SCALARS|NDR_BUFFERS, &r->command);
	# ndr_pull_atsvc_enum_ctr(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.ctr);

	# Three argument version is for structures

    if (/ndr_pull_([^\)]*?)\(ndr, (NDR_[^,]*?), ([^,]*?)\);/ and 
			not NdrParser::is_scalar_type($1)) {
	   	s/(ndr_pull_([^\)]*?)\(
	       ndr,\ 
	       (NDR_[^,]*?),\ 
	       (&?r->((in|out)\.)?([^\(].*?))\);)
		/ndr_pull_$2(ndr, $3, get_subtree(tree, \"$7\", ndr, ett_$2), $4);
	    /smgx;
	}

    # Four argument version if for unions
    if (/ndr_pull_([^\)]*?)\(ndr, (NDR_[SB][^,]*?), ([^,]*?), ([^,]*?)\);/ and
			not NdrParser::is_scalar_type($1)) {
	    s/(ndr_pull_([^\)]*?)\(
	       ndr,\ 
	       (NDR_[^,]*?),\ 
	       (&?r->((in|out)\.)?([^\(].*?))\);)
		/ndr_pull_$2(ndr, $3, get_subtree(tree, \"$2\", ndr, ett_$2), $4);
	    /smgx;
	}

	# Add proto_tree parameter to pull function prototypes, e.g
	#
	# static NTSTATUS ndr_pull_atsvc_JobInfo(struct ndr_pull *ndr, 
	#         int ndr_flags, struct atsvc_JobInfo *r)

	s/^((static\ )?NTSTATUS\ ndr_pull_([^\(]*?)\(
	    struct\ ndr_pull\ \*ndr,\ 
	    int\ (ndr_)?flags)
	    /$1, proto_tree \*tree/smgx;

	# Add proto_tree parameter to ndr_pull_subcontext_flags_fn()

        s/(ndr_pull_subcontext_flags_fn\(ndr)(.*?);/$1, tree$2;/smg;

	# Get rid of ndr_pull_error() calls for the moment. Ethereal
	# should take care of buffer overruns and inconsistent array
	# sizes for us but it would be nice to have some error text in
	# the dissection.

	s/(return ndr_pull_error([^;]*?);)/return NT_STATUS_OK; \/\/ $1/smg;

	# Rename proto_tree args to pidl_tree

	s/(int (ndr_)?flags), proto_tree \*tree/$1, pidl_tree \*tree/smg;

	# Rename struct ndr_pull to struct pidl_pull

	s/struct ndr_pull \*ndr/struct pidl_pull \*ndr/smg;

	# Fix some internal variable declarations

        s/(u?)int(8|16|32) _level;/$1int$2_t _level;/smg;
        s/ndr_pull_([^\(]*)\(ndr,\ tree,\ hf_level,\ &_level\);
            /ndr_pull_$1(ndr, tree, hf_level_$1, &_level);/smgx;

        # Set the end of a structure
       
        s/(ndr_pull_struct_end.*)/$1\tproto_item_set_end(tree->proto_tree, ndr->tvb, ndr->offset);\n/smg;
				
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
	$needed{$x}{strings} = "NULL", if !defined($needed{$x}{strings});
	$needed{$x}{bitmask} = "0", if !defined($needed{$x}{bitmask});
	pidl "\t  { \"$needed{$x}{name}\", \"$x\", $needed{$x}{ft}, $needed{$x}{base}, $needed{$x}{strings}, $needed{$x}{bitmask}, \"$x\", HFILL }},\n";
    }

    pidl "\t};\n\n";

    pidl "\tstatic gint *ett[] = {\n";
    pidl "\t\t&ett_dcerpc_$module,\n";
    foreach my $x (keys(%needed)) {
	pidl "\t\t&$x,\n", if $x =~ /^ett_/;
    }
    pidl "\t};\n\n";
    
    if (defined($if_uuid)) {

	# These can be changed to non-pidl names if the old dissectors
	# in epan/dissctors are deleted.

	my $name = uc($module) . " (pidl)";
	my $short_name = "pidl_$module";
	my $filter_name = "pidl_$module";

	pidl "\tproto_dcerpc_pidl_$module = proto_register_protocol(\"$name\", \"$short_name\", \"$filter_name\");\n\n";

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
