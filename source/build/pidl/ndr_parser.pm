###################################################
# Samba4 NDR parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# Copyright jelmer@samba.org 2004-2005
# released under the GNU GPL

package NdrParser;

use strict;
use needed;
use typelist;
use ndr;

# list of known types
my %typefamily;

sub get_typefamily($)
{
	my $n = shift;
	return $typefamily{$n};
}

# determine if an element needs a "buffers" section in NDR
sub need_buffers_section($)
{
	my $e = shift;
	if (!Ndr::can_contain_deferred($e) &&
	    !util::array_size($e)) {
		return 0;
	}
	return 1;
}

# see if a variable needs to be allocated by the NDR subsystem on pull
sub need_alloc($)
{
	my $e = shift;

	return 0 if (util::has_property($e, "ref") && $e->{PARENT}->{TYPE} eq "FUNCTION");
	return 1 if ($e->{POINTERS} || util::array_size($e));
	return 0;
}

# Prefix to get the actual value of a variable
sub c_ptr_prefix($)
{
	my $e = shift;
	my $pointers = "";
	foreach my $i (Ndr::need_wire_pointer($e)..$e->{POINTERS}-1) { $pointers.="*"; }
	return $pointers;
}

# determine the C prefix used to refer to a variable when passing to a push
# function. This will be '*' for pointers to scalar types, '' for scalar
# types and normal pointers and '&' for pass-by-reference structures
sub c_push_prefix($)
{
	my $e = shift;

	my $ret = "";

	if ($e->{TYPE} =~ "string") {
		$ret = "";
	} elsif (Ndr::is_scalar_type($e->{TYPE}) and $e->{POINTERS} and 
		!util::array_size($e)) {
		$ret .="*";
	} elsif (!Ndr::is_scalar_type($e->{TYPE}) &&
	    !$e->{POINTERS} &&
	    !util::array_size($e)) {
		return "&";
	}

	foreach my $i (2..$e->{POINTERS}) { $ret.="*"; }
	
	return $ret;
}

# determine the C prefix used to refer to a variable when passing to a pull
# return '&' or ''
sub c_pull_prefix($)
{
	my $e = shift;

	if (!$e->{POINTERS} && !util::array_size($e)) {
		return "&";
	}

	if ($e->{TYPE} =~ "string") {
		return "&";
	}

	my $ret = "";
	foreach my $i (2..$e->{POINTERS}) { $ret.="*"; }
	return $ret;
}
my $res = "";
my $tabs = "";
sub pidl($)
{
	my $d = shift;
	if ($d) {
		$res .= $tabs;
		$res .= $d;
	}
	$res .="\n";
}

sub indent()
{
	$tabs .= "\t";
}

sub deindent()
{
	$tabs = substr($tabs, 0, -1);
}

####################################################################
# work out the name of a size_is() variable
sub ParseExpr($$$)
{
	my($e) = shift;
	my($size) = shift;
	my($var_prefix) = shift;

	my($fn) = $e->{PARENT};

	return $size if (util::is_constant($size));

	return $size if ($size =~ /ndr->|\(/);

	my $prefix = "";

	if ($size =~ /\*(.*)/) {
		$size = $1;
		$prefix = "*";
	}

	if ($fn->{TYPE} ne "FUNCTION") {
		return $prefix . "r->$size";
	}

	my $e2 = util::find_sibling($e, $size);

	die("Invalid sibling '$size'") unless defined($e2);

	if (util::has_property($e2, "in") && util::has_property($e2, "out")) {
		return $prefix . "$var_prefix$size";
	}
	
	if (util::has_property($e2, "in")) {
		return $prefix . "r->in.$size";
	}
	
	if (util::has_property($e2, "out")) {
		return $prefix . "r->out.$size";
	}

	die "invalid variable in $size for element $e->{NAME} in $fn->{NAME}\n";
}

#####################################################################
# check that a variable we get from ParseExpr isn't a null pointer
sub check_null_pointer($)
{
	my $size = shift;
	if ($size =~ /^\*/) {
		my $size2 = substr($size, 1);
		pidl "if ($size2 == NULL) return NT_STATUS_INVALID_PARAMETER_MIX;";
	}
}

#####################################################################
# check that a variable we get from ParseExpr isn't a null pointer
# void return varient
sub check_null_pointer_void($)
{
	my $size = shift;
	if ($size =~ /^\*/) {
		my $size2 = substr($size, 1);
		pidl "if ($size2 == NULL) return;";
	}
}

#####################################################################
# work out is a parse function should be declared static or not
sub fn_prefix($)
{
	my $fn = shift;

	if ($fn->{TYPE} eq "TYPEDEF" or 
	    $fn->{TYPE} eq "FUNCTION") {
		return "" if (util::has_property($fn, "public"));
	}

	return "static ";
}

###################################################################
# setup any special flags for an element or structure
sub start_flags($)
{
	my $e = shift;
	my $flags = util::has_property($e, "flag");
	if (defined $flags) {
		pidl "{ uint32_t _flags_save_$e->{TYPE} = ndr->flags;";
		pidl "ndr_set_flags(&ndr->flags, $flags);";
	}
}

###################################################################
# end any special flags for an element or structure
sub end_flags($)
{
	my $e = shift;
	my $flags = util::has_property($e, "flag");
	if (defined $flags) {
		pidl "ndr->flags = _flags_save_$e->{TYPE};\n\t}";
	}
}

#####################################################################
# parse array preceding data - push side
sub ParseArrayPushPreceding($$$)
{
	my $e = shift;
	my $var_prefix = shift;
	my $ndr_flags = shift;

	my $size = ParseExpr($e, util::array_size($e), $var_prefix);

	if (!Ndr::is_inline_array($e)) {
		# we need to emit the array size
		pidl "NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, $size));";
	}
}

#####################################################################
# parse the data of an array - push side
sub ParseArrayPush($$$$)
{
	my $e = shift;
	my $ndr = shift;
	my $var_prefix = shift;
	my $ndr_flags = shift;
	my $cprefix = c_push_prefix($e);

	my $size = ParseExpr($e, util::array_size($e), $var_prefix);

	# See whether the array size has been pushed yet
	if (!Ndr::is_surrounding_array($e)) {
		ParseArrayPushPreceding($e, $var_prefix, $ndr_flags);
	}
	
	if (Ndr::is_varying_array($e)) {
		my $length = util::has_property($e, "length_is");
		$length = ParseExpr($e, $length, $var_prefix);
		pidl "NDR_CHECK(ndr_push_uint32($ndr, NDR_SCALARS, 0));";
		pidl "NDR_CHECK(ndr_push_uint32($ndr, NDR_SCALARS, $length));";
		$size = $length;
	}

	if (Ndr::is_scalar_type($e->{TYPE})) {
		pidl "NDR_CHECK(ndr_push_array_$e->{TYPE}($ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}, $size));";
	} else {
		pidl "NDR_CHECK(ndr_push_array($ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}, sizeof($cprefix$var_prefix$e->{NAME}\[0]), $size, (ndr_push_flags_fn_t)ndr_push_$e->{TYPE}));";
	}
}

#####################################################################
# print an array
sub ParseArrayPrint($$)
{
	my $e = shift;
	my $var_prefix = shift;
	my $size = ParseExpr($e, util::array_size($e), $var_prefix);
	my $cprefix = c_push_prefix($e);

	if (Ndr::is_varying_array($e)) {
		$size = ParseExpr($e, util::has_property($e, "length_is"), $var_prefix);
	}

	if (Ndr::is_scalar_type($e->{TYPE})) {
		pidl "ndr_print_array_$e->{TYPE}(ndr, \"$e->{NAME}\", $cprefix$var_prefix$e->{NAME}, $size);";
	} else {
		pidl "ndr_print_array(ndr, \"$e->{NAME}\", $cprefix$var_prefix$e->{NAME}, sizeof($cprefix$var_prefix$e->{NAME}\[0]), $size, (ndr_print_fn_t)ndr_print_$e->{TYPE});";
	}
}

#####################################################################
# check the size_is and length_is constraints
sub CheckArraySizes($$)
{
	my $e = shift;
	my $var_prefix = shift;

	if (Ndr::is_conformant_array($e)) {
		my $size = ParseExpr($e, util::array_size($e), $var_prefix);
		pidl "if ($var_prefix$e->{NAME}) {";
		indent;
		check_null_pointer($size);
		pidl "NDR_CHECK(ndr_check_array_size(ndr, (void*)&$var_prefix$e->{NAME}, $size));";
		deindent;
		pidl "}";
	}

	if (Ndr::is_varying_array($e)) {
		my $length = util::has_property($e, "length_is");
		$length = ParseExpr($e, $length, $var_prefix);
		pidl "if ($var_prefix$e->{NAME}) {";
		indent;
		check_null_pointer($length);
		pidl "NDR_CHECK(ndr_check_array_length(ndr, (void*)&$var_prefix$e->{NAME}, $length));";
		deindent;
		pidl "}"
	}
}

sub ParseArrayPullPreceding($$$)
{
	my $e = shift;
	my $var_prefix = shift;
	my $ndr_flags = shift;

	if (!Ndr::is_inline_array($e)) {
		# non fixed arrays encode the size just before the array
		pidl "NDR_CHECK(ndr_pull_array_size(ndr, &$var_prefix$e->{NAME}));";
	}
}

#####################################################################
# parse an array - pull side
sub ParseArrayPull($$$$)
{
	my $e = shift;
	my $ndr = shift;
	my $var_prefix = shift;
	my $ndr_flags = shift;

	my $cprefix = c_pull_prefix($e);
	my $length = ParseExpr($e, util::array_size($e), $var_prefix);
	my $size = $length;

	if (Ndr::is_conformant_array($e)) {
		$length = $size = "ndr_get_array_size($ndr, &$var_prefix$e->{NAME})";
	}

	# if this is a conformant array then we use that size to allocate, and make sure
	# we allocate enough to pull the elements
	if (!Ndr::is_inline_array($e) and not Ndr::is_surrounding_array($e)) {
		if ($var_prefix =~ /^r->out/ && $length =~ /^\*r->in/) {
			my $length2 = substr($length, 1);
			pidl "if (ndr->flags & LIBNDR_FLAG_REF_ALLOC) {	NDR_ALLOC($ndr, $length2); }";
		}

		ParseArrayPullPreceding($e, $var_prefix, $ndr_flags);
	}

	if (Ndr::is_varying_array($e)) {
		pidl "NDR_CHECK(ndr_pull_array_length($ndr, &$var_prefix$e->{NAME}));";
		$length = "ndr_get_array_length($ndr, &$var_prefix$e->{NAME})";
	}

	check_null_pointer($length);

	if ($length ne $size) {
		pidl "if ($length > $size) {";
		indent;
		pidl "return ndr_pull_error($ndr, NDR_ERR_CONFORMANT_SIZE, \"Bad conformant size %u should be %u\", $size, $length);";
		deindent;
		pidl "}";
	}

	if ((need_alloc($e) && !Ndr::is_fixed_array($e)) ||
	    ($var_prefix eq "r->in." && util::has_property($e, "ref"))) {
		if (!Ndr::is_inline_array($e) || $ndr_flags eq "NDR_SCALARS") {
			pidl "NDR_ALLOC_N($ndr, $var_prefix$e->{NAME}, $size);";
		}
	}

	if (($var_prefix eq "r->out." && util::has_property($e, "ref"))) {
		if (!Ndr::is_inline_array($e) || $ndr_flags eq "NDR_SCALARS") {
			pidl "if ($ndr->flags & LIBNDR_FLAG_REF_ALLOC) {";
			pidl "\tNDR_ALLOC_N($ndr, $var_prefix$e->{NAME}, $size);";
			pidl "}";
		}
	}

	if (Ndr::is_scalar_type($e->{TYPE})) {
		pidl "NDR_CHECK(ndr_pull_array_$e->{TYPE}($ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}, $length));";
	} else {
		pidl "NDR_CHECK(ndr_pull_array($ndr, $ndr_flags, (void **)$cprefix$var_prefix$e->{NAME}, sizeof($cprefix$var_prefix$e->{NAME}\[0]), $length, (ndr_pull_flags_fn_t)ndr_pull_$e->{TYPE}));";
	}
}

sub compression_alg($)
{
	my $e = shift;
	my $compression = util::has_property($e, "compression");
	my ($alg, $clen, $dlen) = split(/ /, $compression);

	return $alg;
}

sub compression_clen($)
{
	my $e = shift;
	my $compression = util::has_property($e, "compression");
	my ($alg, $clen, $dlen) = split(/ /, $compression);

	return ParseExpr($e, $clen, "r->");
}

sub compression_dlen($)
{
	my $e = shift;
	my $compression = util::has_property($e, "compression");
	my ($alg, $clen, $dlen) = split(/ /, $compression);

	return ParseExpr($e, $dlen, "r->");
}

sub ParseCompressionPushStart($$$)
{
	my $e = shift;
	my $subndr = shift;
	my $ndr_flags = shift;
	my $comndr = $subndr."_compressed";

	pidl "{";
	indent;
	pidl "struct ndr_push *$comndr;";
	pidl "";
	pidl "$comndr = ndr_push_init_ctx($subndr);";
	pidl "if (!$comndr) return NT_STATUS_NO_MEMORY;";
	pidl "$comndr->flags = $subndr->flags;";
	pidl "";
	
	return $comndr;
}

sub ParseCompressionPushEnd($$)
{
	my $e = shift;
	my $subndr = shift;
	my $comndr = $subndr."_compressed";
	my $alg = compression_alg($e);

	pidl "NDR_CHECK(ndr_push_compression($subndr, $comndr, $alg));";
	deindent;
	pidl "}";
}

sub ParseCompressionPullStart($$$)
{
	my $e = shift;
	my $subndr = shift;
	my $ndr_flags = shift;
	my $comndr = $subndr."_compressed";
	my $alg = compression_alg($e);
	my $dlen = compression_dlen($e);

	pidl "{";
	indent;
	pidl "struct ndr_pull *$comndr;";
	pidl "NDR_ALLOC($subndr, $comndr);";
	pidl "NDR_CHECK(ndr_pull_compression($subndr, $comndr, $alg, $dlen));";

	return $comndr;
}

sub ParseCompressionPullEnd($$)
{
	my $e = shift;
	my $subndr = shift;
	my $comndr = $subndr."_compressed";

	deindent;
	pidl "}";
}

sub ParseSubcontextPushStart($$)
{
	my $e = shift;
	my $ndr_flags = shift;
	my $compression = util::has_property($e, "compression");
	my $retndr;

	pidl "if (($ndr_flags) & NDR_SCALARS) {";
	indent;
	pidl "struct ndr_push *_ndr_$e->{NAME};";
	pidl "";
	pidl "_ndr_$e->{NAME} = ndr_push_init_ctx(ndr);";
	pidl "if (!_ndr_$e->{NAME}) return NT_STATUS_NO_MEMORY;";
	pidl "_ndr_$e->{NAME}->flags = ndr->flags;";
	pidl "";
	
	$retndr = "_ndr_$e->{NAME}";

	if (defined $compression) {
		$retndr = ParseCompressionPushStart($e, $retndr, "NDR_SCALARS");
	}
	
	return $retndr
}

sub ParseSubcontextPushEnd($)
{
	my $e = shift;
	my $header_size = util::has_property($e, "subcontext");
	my $size_is = util::has_property($e, "subcontext_size");
	my $compression = util::has_property($e, "compression");
	my $ndr = "_ndr_$e->{NAME}";

	if (defined $compression) {
		ParseCompressionPushEnd($e, $ndr);
	}

	if (not defined($size_is)) {
		$size_is = "-1";
	}

	pidl "NDR_CHECK(ndr_push_subcontext_header(ndr, $header_size, $size_is, $ndr));";
	pidl "NDR_CHECK(ndr_push_bytes(ndr, $ndr->data, $ndr->offset));";
	deindent;
	pidl "}";
}

sub ParseSubcontextPullStart($$)
{
	my $e = shift;
	my $ndr_flags = shift;	
	my $header_size = util::has_property($e, "subcontext");
	my $size_is = util::has_property($e, "subcontext_size");
	my $retndr = "_ndr_$e->{NAME}";
	my $compression = util::has_property($e, "compression");

	if (not defined($size_is)) {
		$size_is = "-1";
	}

	pidl "if (($ndr_flags) & NDR_SCALARS) {";
	indent;
	pidl "struct ndr_pull *$retndr;";
	pidl "NDR_ALLOC(ndr, $retndr);";
	pidl "NDR_CHECK(ndr_pull_subcontext_header(ndr, $header_size, $size_is, $retndr));"; 

	if (defined $compression) {
		$retndr = ParseCompressionPullStart($e, $retndr, $ndr_flags);
	}
	
	return $retndr;
}

sub ParseSubcontextPullEnd($)
{
	my $e = shift;
	my $header_size = util::has_property($e, "subcontext");
	my $size_is = util::has_property($e, "subcontext_size");
	my $subndr = "_ndr_$e->{NAME}";
	my $compression = util::has_property($e, "compression");

	if (defined $compression) {
		ParseCompressionPullEnd($e, $subndr);
	}

	my $advance;
	if (defined ($size_is)) {
		$advance = "$size_is";	
	} elsif ($header_size) {
		$advance = "$subndr->data_size";
	} else {
		$advance = "$subndr->offset";
	}
	pidl "NDR_CHECK(ndr_pull_advance(ndr, $advance));";
	deindent;
	pidl "}";
}

#####################################################################
# parse scalars in a structure element
sub ParseElementPushScalar($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $cprefix = c_push_prefix($e);
	my $ptr_prefix = c_ptr_prefix($e);
	my $sub_size = util::has_property($e, "subcontext");
	my $ndr = "ndr";
	my $subndr = undef;

	start_flags($e);

	if (my $value = util::has_property($e, "value")) {
		pidl "$cprefix$var_prefix$e->{NAME} = $value;";
	}

	if (defined $sub_size and $e->{POINTERS} == 0) {
		$subndr = ParseSubcontextPushStart($e, "NDR_SCALARS");
		$ndr = $subndr;
	}

	if (Ndr::need_wire_pointer($e)) {
		ParsePtrPush($e, $ptr_prefix.$var_prefix);
	} elsif (Ndr::is_inline_array($e)) {
		ParseArrayPush($e, $ndr, "r->", "NDR_SCALARS");
	} elsif (need_alloc($e)) {
		# no scalar component
	} else {
		if (my $switch = util::has_property($e, "switch_is")) {
			ParseSwitchPush($e, $ndr, $var_prefix, $ndr_flags, $switch);
		}

		pidl "NDR_CHECK(ndr_push_$e->{TYPE}($ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));";
	}

	if (defined $sub_size and $e->{POINTERS} == 0) {
		ParseSubcontextPushEnd($e);
	}

	end_flags($e);
}

#####################################################################
# parse a pointer in a struct element or function
sub ParsePtrPush($$)
{
	my $e = shift;
	my $var_prefix = shift;

	if (util::has_property($e, "ref")) {
		pidl "NDR_CHECK(ndr_push_ref_ptr(ndr, $var_prefix$e->{NAME}));";
	} elsif (util::has_property($e, "relative")) {
		pidl "NDR_CHECK(ndr_push_relative_ptr1(ndr, $var_prefix$e->{NAME}));";
	} else {
		pidl "NDR_CHECK(ndr_push_unique_ptr(ndr, $var_prefix$e->{NAME}));";
	}
}

#####################################################################
# print scalars in a structure element
sub ParseElementPrint($$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my $cprefix = c_push_prefix($e);
	my $ptr_prefix = c_ptr_prefix($e);

	return if (util::has_property($e, "noprint"));

	if (my $value = util::has_property($e, "value")) {
		pidl "if (ndr->flags & LIBNDR_PRINT_SET_VALUES) {";
		pidl "\t$cprefix$var_prefix$e->{NAME} = $value;";
		pidl "}";
	}

	my $l = $e->{POINTERS};
	$l++ if (util::array_size($e) and $l == 0 and !Ndr::is_fixed_array($e));

	foreach my $i (1..$l) {
		pidl "ndr_print_ptr(ndr, \"$e->{NAME}\", $var_prefix$e->{NAME});";
		pidl "ndr->depth++;";
		if ($i > $l-Ndr::need_wire_pointer($e)) {
			pidl "if ($ptr_prefix$var_prefix$e->{NAME}) {";
			indent;
		}
	}

	if (util::array_size($e)) {
		ParseArrayPrint($e, $var_prefix)
	} else {
		if (my $switch = util::has_property($e, "switch_is")) {
			my $switch_var = ParseExpr($e, $switch, $var_prefix);
			check_null_pointer_void($switch_var);

			pidl "ndr_print_set_switch_value(ndr, $cprefix$var_prefix$e->{NAME}, $switch_var);";
		}

		pidl "ndr_print_$e->{TYPE}(ndr, \"$e->{NAME}\", $cprefix$var_prefix$e->{NAME});";
	}

	foreach my $i (1..$l) {
		if ($i > $l-Ndr::need_wire_pointer($e)) {
			deindent;
			pidl "}";
		}
		pidl "ndr->depth--;";
	}
}

#####################################################################
# parse scalars in a structure element - pull size
sub ParseSwitchPull($$$$$)
{
	my($e) = shift;
	my $ndr = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $switch = shift;
	my $switch_var = ParseExpr($e, $switch, $var_prefix);

	my $cprefix = c_pull_prefix($e);

	my $utype = typelist::getType($e->{TYPE});

	check_null_pointer($switch_var);

	pidl "NDR_CHECK(ndr_pull_set_switch_value($ndr, $cprefix$var_prefix$e->{NAME}, $switch_var));";

}

#####################################################################
# push switch element
sub ParseSwitchPush($$$$$)
{
	my($e) = shift;
	my $ndr = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $switch = shift;
	my $switch_var = ParseExpr($e, $switch, $var_prefix);
	my $cprefix = c_push_prefix($e);

	check_null_pointer($switch_var);

	pidl "NDR_CHECK(ndr_push_set_switch_value($ndr, $cprefix$var_prefix$e->{NAME}, $switch_var));";

}

#####################################################################
# parse scalars in a structure element - pull size
sub ParseElementPullScalar($$$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my($ndr_flags) = shift;
	my $cprefix = c_pull_prefix($e);
	my $ptr_prefix = c_ptr_prefix($e);
	my $sub_size = util::has_property($e, "subcontext");
	my $ndr = "ndr";
	my $subndr = undef;

	start_flags($e);

	if (defined $sub_size && $e->{POINTERS} == 0) {
		$subndr = ParseSubcontextPullStart($e, $ndr_flags);
		$ndr = $subndr;
		$ndr_flags = "NDR_SCALARS|NDR_BUFFERS";
	}

	if (Ndr::is_inline_array($e)) {
		ParseArrayPull($e, $ndr, "r->", "NDR_SCALARS");
	} elsif (Ndr::need_wire_pointer($e)) {
		ParsePtrPull($e, $ptr_prefix.$var_prefix);
	} elsif (Ndr::is_surrounding_array($e)) {
	} else {
		if (my $switch = util::has_property($e, "switch_is")) {
			ParseSwitchPull($e, $ndr, $var_prefix, $ndr_flags, $switch);
		}

		pidl "NDR_CHECK(ndr_pull_$e->{TYPE}($ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));";
	}

	if (my $range = util::has_property($e, "range")) {
		my ($low, $high) = split(/ /, $range, 2);
		pidl "if ($var_prefix$e->{NAME} < $low || $var_prefix$e->{NAME} > $high) {";
		pidl "\treturn ndr_pull_error($ndr, NDR_ERR_RANGE, \"value out of range\");";
		pidl "}";
	}

	if (defined $sub_size && $e->{POINTERS} == 0) {
		ParseSubcontextPullEnd($e);
	}

	end_flags($e);
}

#####################################################################
# parse a pointer in a struct element or function
sub ParsePtrPull($$)
{
	my($e) = shift;
	my($var_prefix) = shift;

	if (util::has_property($e, "ref")) {
		pidl "NDR_CHECK(ndr_pull_ref_ptr(ndr, &_ptr_$e->{NAME}));";
	} else {
		pidl "NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_$e->{NAME}));";
	}
	pidl "if (_ptr_$e->{NAME}) {";
	indent;
	pidl "NDR_ALLOC(ndr, $var_prefix$e->{NAME});";
	if (util::has_property($e, "relative")) {
		pidl "NDR_CHECK(ndr_pull_relative_ptr1(ndr, $var_prefix$e->{NAME}, _ptr_$e->{NAME}));";
	}
	deindent;
	pidl "} else {";
	pidl "\t$var_prefix$e->{NAME} = NULL;";
	pidl "}";
}

#####################################################################
# parse buffers in a structure element
sub ParseElementPushBuffer($$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my $cprefix = c_push_prefix($e);
	my $sub_size = util::has_property($e, "subcontext");
	my $ndr = "ndr";
	my $subndr = undef;

	return unless (need_buffers_section($e));

	start_flags($e);

	my $pointers = c_ptr_prefix($e);
	for my $i (1..Ndr::need_wire_pointer($e)) {
		if ($i > 1) {
			ParsePtrPush($e,$pointers.$var_prefix);
		}
		pidl "if ($pointers$var_prefix$e->{NAME}) {";
		indent;
		$pointers.="*";
	}
	
	if (util::has_property($e, "relative")) {
		pidl "NDR_CHECK(ndr_push_relative_ptr2(ndr, $var_prefix$e->{NAME}));";
	}

	my $ndr_flags = "NDR_BUFFERS";
	if ($e->{POINTERS} || (util::array_size($e) && !Ndr::is_inline_array($e)))
	{
		$ndr_flags="NDR_SCALARS|$ndr_flags" 
	}

	if (defined $sub_size) {
		$subndr = ParseSubcontextPushStart($e, $ndr_flags);
		$ndr = $subndr;
		$ndr_flags = "NDR_SCALARS|NDR_BUFFERS";
	}

	if (util::array_size($e)) {
		ParseArrayPush($e, $ndr, "r->", $ndr_flags);
	} else {
		if (my $switch = util::has_property($e, "switch_is")) {
			ParseSwitchPush($e, $ndr, $var_prefix, $ndr_flags, $switch);
		}

		pidl "NDR_CHECK(ndr_push_$e->{TYPE}($ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));";
	}

	if (defined $sub_size) {
		ParseSubcontextPushEnd($e);
	}

	for my $i (1..Ndr::need_wire_pointer($e)) {
		deindent;
		pidl "}";
	}

	end_flags($e);
}

#####################################################################
# parse buffers in a structure element - pull side
sub ParseElementPullBuffer($$)
{
	my($e) = shift;
	my($var_prefix) = shift;
	my $cprefix = c_pull_prefix($e);
	my $sub_size = util::has_property($e, "subcontext");
	my $ndr = "ndr";
	my $subndr = undef;

	return unless (need_buffers_section($e));

	start_flags($e);

 	my $pointers = c_ptr_prefix($e);
 	for my $i (1..Ndr::need_wire_pointer($e)) {
 		if ($i > 1) {
 			ParsePtrPull($e,$pointers.$var_prefix);
 		}
 		pidl "if ($pointers$var_prefix$e->{NAME}) {";
 		indent;
 		$pointers.="*";
 	}
 
 	if (util::has_property($e, "relative")) {
 		pidl "struct ndr_pull_save _relative_save;";
 		pidl "ndr_pull_save(ndr, &_relative_save);";
 		pidl "NDR_CHECK(ndr_pull_relative_ptr2(ndr, $var_prefix$e->{NAME}));";
 	}

	my $ndr_flags = "NDR_BUFFERS";
	if ($e->{POINTERS} || (util::array_size($e) && !Ndr::is_inline_array($e)))
	{
		$ndr_flags="NDR_SCALARS|$ndr_flags" 
	}

	if (defined $sub_size) {
		$subndr = ParseSubcontextPullStart($e, $ndr_flags);
		$ndr = $subndr;
		$ndr_flags = "NDR_SCALARS|NDR_BUFFERS";
	}

	if (util::array_size($e)) {
		ParseArrayPull($e, $ndr, "r->", $ndr_flags);
	} else {
		if (my $switch = util::has_property($e, "switch_is")) {
			ParseSwitchPull($e, $ndr, $var_prefix, $ndr_flags, $switch);
		}

		pidl "NDR_CHECK(ndr_pull_$e->{TYPE}($ndr, $ndr_flags, $cprefix$var_prefix$e->{NAME}));";
	}

	if (defined $sub_size) {
		ParseSubcontextPullEnd($e);
	}

	if (util::has_property($e, "relative")) {
		pidl "ndr_pull_restore(ndr, &_relative_save);";
	}

	for my $i (1..Ndr::need_wire_pointer($e)) {
		deindent;
		pidl "}";
	}

	end_flags($e);
}

#####################################################################
# parse a struct
sub ParseStructPush($)
{
	my($struct) = shift;
	
	return unless defined($struct->{ELEMENTS});

	start_flags($struct);

	# see if the structure contains a conformant array. If it
	# does, then it must be the last element of the structure, and
	# we need to push the conformant length early, as it fits on
	# the wire before the structure (and even before the structure
	# alignment)
	my $e = $struct->{ELEMENTS}[-1];
	if (Ndr::is_conformant_array($e) and Ndr::is_surrounding_array($e)) {
		ParseArrayPushPreceding($e, "r->", "NDR_SCALARS");
	}

	if (defined $e->{TYPE} && $e->{TYPE} eq "string" 
	    &&  util::property_matches($e, "flag", ".*LIBNDR_FLAG_STR_CONFORMANT.*")) {
		pidl "NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ndr_string_array_size(ndr, r->$e->{NAME})));";
	}

	pidl "if (!(ndr_flags & NDR_SCALARS)) goto buffers;";

	pidl "NDR_CHECK(ndr_push_struct_start(ndr));";

	my $align = Ndr::find_largest_alignment($struct);
	pidl "NDR_CHECK(ndr_push_align(ndr, $align));";

	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPushScalar($e, "r->", "NDR_SCALARS");
	}	

	pidl "buffers:";
	pidl "if (!(ndr_flags & NDR_BUFFERS)) goto done;";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPushBuffer($e, "r->");
	}

	pidl "ndr_push_struct_end(ndr);";

	pidl "done:";

	end_flags($struct);
}

#####################################################################
# generate a push function for an enum
sub ParseEnumPush($)
{
	my($enum) = shift;
	my($type_fn) = typelist::enum_type_fn($enum);

	start_flags($enum);

	pidl "NDR_CHECK(ndr_push_$type_fn(ndr, NDR_SCALARS, r));";

	end_flags($enum);
}

#####################################################################
# generate a pull function for an enum
sub ParseEnumPull($)
{
	my($enum) = shift;
	my($type_fn) = typelist::enum_type_fn($enum);
	my($type_v_decl) = typelist::mapScalarType(typelist::enum_type_fn($enum));

	pidl "$type_v_decl v;";
	start_flags($enum);
	pidl "NDR_CHECK(ndr_pull_$type_fn(ndr, NDR_SCALARS, &v));";
	pidl "*r = v;";

	end_flags($enum);
}

#####################################################################
# generate a print function for an enum
sub ParseEnumPrint($)
{
	my($enum) = shift;

	pidl "const char *val = NULL;";
	pidl "";

	start_flags($enum);

	pidl "switch (r) {";
	indent;
	my $els = \@{$enum->{ELEMENTS}};
	foreach my $i (0 .. $#{$els}) {
		my $e = ${$els}[$i];
		chomp $e;
		if ($e =~ /^(.*)=/) {
			$e = $1;
		}
		pidl "case $e: val = \"$e\"; break;";
	}

	deindent;
	pidl "}";
	
	pidl "ndr_print_enum(ndr, name, \"$enum->{TYPE}\", val, r);";

	end_flags($enum);
}

sub ArgsEnumPush($)
{
	my $e = shift;
	return "struct ndr_push *ndr, int ndr_flags, enum $e->{NAME} r";
}

sub ArgsEnumPrint($)
{
	my $e = shift;
	return "struct ndr_print *ndr, const char *name, enum $e->{NAME} r";
}

sub ArgsEnumPull($)
{
	my $e = shift;
	return "struct ndr_pull *ndr, int ndr_flags, enum $e->{NAME} *r";
}

$typefamily{ENUM} = {
	PUSH_FN_BODY => \&ParseEnumPush,
	PUSH_FN_ARGS => \&ArgsEnumPush,
	PULL_FN_BODY => \&ParseEnumPull,
	PULL_FN_ARGS => \&ArgsEnumPull,
	PRINT_FN_BODY => \&ParseEnumPrint,
	PRINT_FN_ARGS => \&ArgsEnumPrint,
};

#####################################################################
# generate a push function for a bitmap
sub ParseBitmapPush($)
{
	my($bitmap) = shift;
	my($type_fn) = typelist::bitmap_type_fn($bitmap);

	start_flags($bitmap);

	pidl "NDR_CHECK(ndr_push_$type_fn(ndr, NDR_SCALARS, r));";

	end_flags($bitmap);
}

#####################################################################
# generate a pull function for an bitmap
sub ParseBitmapPull($)
{
	my($bitmap) = shift;
	my($type_fn) = typelist::bitmap_type_fn($bitmap);
	my($type_decl) = typelist::mapType($bitmap);

	pidl "$type_decl v;";
	start_flags($bitmap);
	pidl "NDR_CHECK(ndr_pull_$type_fn(ndr, NDR_SCALARS, &v));";
	pidl "*r = v;";

	end_flags($bitmap);
}

#####################################################################
# generate a print function for an bitmap
sub ParseBitmapPrintElement($$)
{
	my($e) = shift;
	my($bitmap) = shift;
	my($type_decl) = typelist::mapType($bitmap);
	my($type_fn) = typelist::bitmap_type_fn($bitmap);
	my($name) = $bitmap->{PARENT}->{NAME};
	my($flag);

	if ($e =~ /^(\w+) .*$/) {
		$flag = "$1";
	} else {
		die "Bitmap: \"$name\" invalid Flag: \"$e\"";
	}

	pidl "ndr_print_bitmap_flag(ndr, sizeof($type_decl), \"$flag\", $flag, r);";
}

#####################################################################
# generate a print function for an bitmap
sub ParseBitmapPrint($)
{
	my($bitmap) = shift;
	my($type_decl) = typelist::mapType($bitmap);
	my($type_fn) = typelist::bitmap_type_fn($bitmap);

	start_flags($bitmap);

	pidl "ndr_print_$type_fn(ndr, name, r);";

	pidl "ndr->depth++;";
	foreach my $e (@{$bitmap->{ELEMENTS}}) {
		ParseBitmapPrintElement($e, $bitmap);
	}
	pidl "ndr->depth--;";

	end_flags($bitmap);
}

sub ArgsBitmapPush($)
{
	my $e = shift;
	my $type_decl = typelist::mapType($e->{DATA});
	return "struct ndr_push *ndr, int ndr_flags, $type_decl r";
}

sub ArgsBitmapPrint($)
{
	my $e = shift;
	my $type_decl = typelist::mapType($e->{DATA});
	return "struct ndr_print *ndr, const char *name, $type_decl r";
}

sub ArgsBitmapPull($)
{
	my $e = shift;
	my $type_decl = typelist::mapType($e->{DATA});
	return "struct ndr_pull *ndr, int ndr_flags, $type_decl *r";
}

$typefamily{BITMAP} = {
	PUSH_FN_BODY => \&ParseBitmapPush,
	PUSH_FN_ARGS => \&ArgsBitmapPush,
	PULL_FN_BODY => \&ParseBitmapPull,
	PULL_FN_ARGS => \&ArgsBitmapPull,
	PRINT_FN_BODY => \&ParseBitmapPrint,
	PRINT_FN_ARGS => \&ArgsBitmapPrint,
};

#####################################################################
# generate a struct print function
sub ParseStructPrint($)
{
	my($struct) = shift;
	my($name) = $struct->{PARENT}->{NAME};

	return unless defined $struct->{ELEMENTS};

	pidl "ndr_print_struct(ndr, name, \"$name\");";

	start_flags($struct);

	pidl "ndr->depth++;";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPrint($e, "r->");
	}
	pidl "ndr->depth--;";

	end_flags($struct);
}

#####################################################################
# parse a struct - pull side
sub ParseStructPull($)
{
	my($struct) = shift;
	my $conform_e;

	return unless defined $struct->{ELEMENTS};

	# see if the structure contains a conformant array. If it
	# does, then it must be the last element of the structure, and
	# we need to pull the conformant length early, as it fits on
	# the wire before the structure (and even before the structure
	# alignment)
	my $e = $struct->{ELEMENTS}[-1];
	if (Ndr::is_conformant_array($e) and Ndr::is_surrounding_array($e)) {
		$conform_e = $e;
	}

	if (defined $e->{TYPE} && $e->{TYPE} eq "string"
	    &&  util::property_matches($e, "flag", ".*LIBNDR_FLAG_STR_CONFORMANT.*")) {
		$conform_e = $e;
	}

	# declare any internal pointers we need
	foreach my $e (@{$struct->{ELEMENTS}}) {
		if (Ndr::need_wire_pointer($e)) {
			pidl "uint32_t _ptr_$e->{NAME};";
		}
	}

	start_flags($struct);

	pidl "if (!(ndr_flags & NDR_SCALARS)) goto buffers;";

	pidl "NDR_CHECK(ndr_pull_struct_start(ndr));";

	if (defined $conform_e) {
		ParseArrayPullPreceding($conform_e, "r->", "NDR_SCALARS");
	}

	my $align = Ndr::find_largest_alignment($struct);
	pidl "NDR_CHECK(ndr_pull_align(ndr, $align));";

	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPullScalar($e, "r->", "NDR_SCALARS");
	}	

	pidl "buffers:\n";
	pidl "if (!(ndr_flags & NDR_BUFFERS)) goto done;";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPullBuffer($e, "r->");
	}

	foreach my $e (@{$struct->{ELEMENTS}}) {
		CheckArraySizes($e, "r->");
	}

	pidl "ndr_pull_struct_end(ndr);";

	pidl "done:";

	end_flags($struct);
}

#####################################################################
# calculate size of ndr struct
sub ParseStructNdrSize($)
{
	my $t = shift;
	my $static = fn_prefix($t);
	my $sizevar;

	if (my $flags = util::has_property($t, "flag")) {
		pidl "flags |= $flags;";
	}
	pidl "return ndr_size_struct(r, flags, (ndr_push_flags_fn_t)ndr_push_$t->{NAME});";
}

sub ArgsStructPush($)
{
	my $e = shift;
	return "struct ndr_push *ndr, int ndr_flags, struct $e->{NAME} *r";
}

sub ArgsStructPrint($)
{
	my $e = shift;
	return "struct ndr_print *ndr, const char *name, struct $e->{NAME} *r";
}

sub ArgsStructPull($)
{
	my $e = shift;
	return "struct ndr_pull *ndr, int ndr_flags, struct $e->{NAME} *r";
}

sub ArgsStructNdrSize($)
{
	my $d = shift;
	return "const struct $d->{NAME} *r, int flags";
}

$typefamily{STRUCT} = {
	PUSH_FN_BODY => \&ParseStructPush,
	PUSH_FN_ARGS => \&ArgsStructPush,
	PULL_FN_BODY => \&ParseStructPull,
	PULL_FN_ARGS => \&ArgsStructPull,
	PRINT_FN_BODY => \&ParseStructPrint,
	PRINT_FN_ARGS => \&ArgsStructPrint,
	SIZE_FN_BODY => \&ParseStructNdrSize,
	SIZE_FN_ARGS => \&ArgsStructNdrSize,
};

#####################################################################
# calculate size of ndr struct
sub ParseUnionNdrSize($)
{
	my $t = shift;
	my $static = fn_prefix($t);
	my $sizevar;

	if (my $flags = util::has_property($t, "flag")) {
		pidl "flags |= $flags;";
	}

	pidl "return ndr_size_union(r, flags, level, (ndr_push_flags_fn_t)ndr_push_$t->{NAME});";
}

#####################################################################
# parse a union - push side
sub ParseUnionPush($)
{
	my $e = shift;
	my $have_default = 0;

	pidl "int level;";

	start_flags($e);

	pidl "level = ndr_push_get_switch_value(ndr, r);";

	pidl "if (!(ndr_flags & NDR_SCALARS)) goto buffers;";

	if (!util::has_property($e, "nodiscriminant")) {
		my $switch_type = util::has_property($e, "switch_type");
		$switch_type = "uint32" unless  (defined ($switch_type));
		pidl "NDR_CHECK(ndr_push_$switch_type(ndr, NDR_SCALARS, level));";
	}

	pidl "NDR_CHECK(ndr_push_struct_start(ndr));";

#	my $align = union_alignment($e);
#	pidl "NDR_CHECK(ndr_push_align(ndr, $align));";

	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			pidl "default:";
			$have_default = 1;
		} else {
			pidl "case $el->{PROPERTIES}->{case}:";

		}
		if ($el->{TYPE} ne "EMPTY") {
			indent;
			ParseElementPushScalar($el, "r->", "NDR_SCALARS");
			deindent;
		}
		pidl "break;";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);";
	}
	deindent;
	pidl "}";
	pidl "buffers:";
	pidl "if (!(ndr_flags & NDR_BUFFERS)) goto done;";
	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			pidl "default:";
		} else {
			pidl "case $el->{PROPERTIES}->{case}:";
		}
		if ($el->{TYPE} ne "EMPTY") {
			indent;
			ParseElementPushBuffer($el, "r->");
			deindent;
		}
		pidl "break;";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);";
	}
	deindent;
	pidl "}";
	pidl "ndr_push_struct_end(ndr);";
	pidl "done:";
	end_flags($e);
}

#####################################################################
# print a union
sub ParseUnionPrint($)
{
	my $e = shift;
	my $have_default = 0;
	my($name) = $e->{PARENT}->{NAME};

	pidl "int level = ndr_print_get_switch_value(ndr, r);";

	pidl "ndr_print_union(ndr, name, level, \"$name\");";
	start_flags($e);

	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			$have_default = 1;
			pidl "default:";
		} else {
			pidl "case $el->{PROPERTIES}->{case}:";
		}
		if ($el->{TYPE} ne "EMPTY") {
			indent;
			ParseElementPrint($el, "r->");
			deindent;
		}
		pidl "break;";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\tndr_print_bad_level(ndr, name, level);";
	}
	deindent;
	pidl "}";

	end_flags($e);
}

#####################################################################
# parse a union - pull side
sub ParseUnionPull($)
{
	my $e = shift;
	my $have_default = 0;
	my $switch_type = util::has_property($e, "switch_type");
	$switch_type = "uint32" unless defined($switch_type);

	pidl "int level;";
	if (!util::has_property($e, "nodiscriminant")) {
		if (typelist::typeIs($switch_type, "ENUM")) {
			$switch_type = typelist::enum_type_fn(typelist::getType($switch_type));
		}
		pidl typelist::mapScalarType($switch_type) . " _level;";
	}

	start_flags($e);

	pidl "level = ndr_pull_get_switch_value(ndr, r);";

	pidl "if (!(ndr_flags & NDR_SCALARS)) goto buffers;";

	if (!util::has_property($e, "nodiscriminant")) {
		pidl "NDR_CHECK(ndr_pull_$switch_type(ndr, NDR_SCALARS, &_level));";
		pidl "if (_level != level) {"; 
		pidl "\treturn ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value %u for $e->{PARENT}->{NAME}\", _level);";
		pidl "}";
	}

	pidl "NDR_CHECK(ndr_pull_struct_start(ndr));";

#	my $align = union_alignment($e);
#	pidl "\tNDR_CHECK(ndr_pull_align(ndr, $align));\n";

	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			pidl "default: {";
			$have_default = 1;
		} else {
			pidl "case $el->{PROPERTIES}->{case}: {";
		}
		if ($el->{TYPE} ne "EMPTY") {
			indent;
			if ($el->{POINTERS}) {
				pidl "uint32_t _ptr_$el->{NAME};";
			}
			ParseElementPullScalar($el, "r->", "NDR_SCALARS");
			deindent;
		}
		pidl "break; }";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);";
	}
	deindent;
	pidl "}";
	pidl "buffers:";
	pidl "if (!(ndr_flags & NDR_BUFFERS)) goto done;";
	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if (util::has_property($el, "default")) {
			pidl "default:";
		} else {
			pidl "case $el->{PROPERTIES}->{case}:";
		}
		if ($el->{TYPE} ne "EMPTY") {
			indent;
			ParseElementPullBuffer($el, "r->");
			deindent;
		}
		pidl "break;";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);";
	}
	deindent;
	pidl "}";
	pidl "ndr_pull_struct_end(ndr);";
	pidl "done:";
	end_flags($e);
}

sub ArgsUnionPush($)
{
	my $e = shift;
	return "struct ndr_push *ndr, int ndr_flags, union $e->{NAME} *r";
}

sub ArgsUnionPrint($)
{
	my $e = shift;
	return "struct ndr_print *ndr, const char *name, union $e->{NAME} *r";
}

sub ArgsUnionPull($)
{
	my $e = shift;
	return "struct ndr_pull *ndr, int ndr_flags, union $e->{NAME} *r";
}

sub ArgsUnionNdrSize($)
{
	my $d = shift;
	return "const union $d->{NAME} *r, uint32_t level, int flags";
}

$typefamily{UNION} = {
	PUSH_FN_BODY => \&ParseUnionPush,
	PUSH_FN_ARGS => \&ArgsUnionPush,
	PULL_FN_BODY => \&ParseUnionPull,
	PULL_FN_ARGS => \&ArgsUnionPull,
	PRINT_FN_BODY => \&ParseUnionPrint,
	PRINT_FN_ARGS => \&ArgsUnionPrint,
	SIZE_FN_ARGS => \&ArgsUnionNdrSize,
	SIZE_FN_BODY => \&ParseUnionNdrSize,
};
	
#####################################################################
# parse a typedef - push side
sub ParseTypedefPush($)
{
	my($e) = shift;
	my $static = fn_prefix($e);

	return unless needed::is_needed("push_$e->{NAME}");

	my $args = $typefamily{$e->{DATA}->{TYPE}}->{PUSH_FN_ARGS}->($e);
	pidl $static . "NTSTATUS ndr_push_$e->{NAME}($args)";

	pidl "{";
	indent;
	$typefamily{$e->{DATA}->{TYPE}}->{PUSH_FN_BODY}->($e->{DATA});
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";
	pidl "";;
}


#####################################################################
# parse a typedef - pull side
sub ParseTypedefPull($)
{
	my($e) = shift;
	my $static = fn_prefix($e);

	return unless needed::is_needed("pull_$e->{NAME}");

	my $args = $typefamily{$e->{DATA}->{TYPE}}->{PULL_FN_ARGS}->($e);

	pidl $static . "NTSTATUS ndr_pull_$e->{NAME}($args)";

	pidl "{";
	indent;
	$typefamily{$e->{DATA}->{TYPE}}->{PULL_FN_BODY}->($e->{DATA});
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# parse a typedef - print side
sub ParseTypedefPrint($)
{
	my($e) = shift;

	my $args = $typefamily{$e->{DATA}->{TYPE}}->{PRINT_FN_ARGS}->($e);

	return unless !util::has_property($e, "noprint");

	pidl "void ndr_print_$e->{NAME}($args)";
	pidl "{";
	indent;
	$typefamily{$e->{DATA}->{TYPE}}->{PRINT_FN_BODY}->($e->{DATA});
	deindent;
	pidl "}";
}

#####################################################################
## calculate the size of a structure
sub ParseTypedefNdrSize($)
{
	my($t) = shift;

	return unless needed::is_needed("ndr_size_$t->{NAME}");

	my $tf = $typefamily{$t->{DATA}->{TYPE}};
	my $args = $tf->{SIZE_FN_ARGS}->($t);

	pidl "size_t ndr_size_$t->{NAME}($args)";
	pidl "{";
	indent;
	$typefamily{$t->{DATA}->{TYPE}}->{SIZE_FN_BODY}->($t);
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# parse a function - print side
sub ParseFunctionPrint($)
{
	my($fn) = shift;

	return unless !util::has_property($fn, "noprint");

	pidl "void ndr_print_$fn->{NAME}(struct ndr_print *ndr, const char *name, int flags, struct $fn->{NAME} *r)";
	pidl "{";
	indent;
	pidl "ndr_print_struct(ndr, name, \"$fn->{NAME}\");";
	pidl "ndr->depth++;";

	pidl "if (flags & NDR_SET_VALUES) {";
	pidl "\tndr->flags |= LIBNDR_PRINT_SET_VALUES;";
	pidl "}";

	pidl "if (flags & NDR_IN) {";
	indent;
	pidl "ndr_print_struct(ndr, \"in\", \"$fn->{NAME}\");";
	pidl "ndr->depth++;";

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "in")) {
			ParseElementPrint($e, "r->in.");
		}
	}
	pidl "ndr->depth--;";
	deindent;
	pidl "}";
	
	pidl "if (flags & NDR_OUT) {";
	indent;
	pidl "ndr_print_struct(ndr, \"out\", \"$fn->{NAME}\");";
	pidl "ndr->depth++;";
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "out")) {
			ParseElementPrint($e, "r->out.");
		}
	}
	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		my $cprefix = "&";
		$cprefix = "" if (Ndr::is_scalar_type($fn->{RETURN_TYPE})) ; # FIXME: Should really use util::c_push_prefix here
		pidl "ndr_print_$fn->{RETURN_TYPE}(ndr, \"result\", $cprefix"."r->out.result);";
	}
	pidl "ndr->depth--;";
	deindent;
	pidl "}";
	
	pidl "ndr->depth--;";
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# parse a function element
sub ParseFunctionElementPush($$)
{ 
	my $e = shift;
	my $inout = shift;

	if (util::array_size($e)) {
		if (Ndr::need_wire_pointer($e)) {
			ParsePtrPush($e, "r->$inout.");
			pidl "if (r->$inout.$e->{NAME}) {";
			indent;
			ParseArrayPush($e, "ndr", "r->$inout.", "NDR_SCALARS|NDR_BUFFERS");
			deindent;
			pidl "}";
		} else {
			ParseArrayPush($e, "ndr", "r->$inout.", "NDR_SCALARS|NDR_BUFFERS");
		}
	} else {
		ParseElementPushScalar($e, "r->$inout.", "NDR_SCALARS|NDR_BUFFERS");
		if (Ndr::need_wire_pointer($e)) {
			ParseElementPushBuffer($e, "r->$inout.");
		}
	}
}	

#####################################################################
# parse a function
sub ParseFunctionPush($)
{ 
	my($fn) = shift;
	my $static = fn_prefix($fn);

	return unless !util::has_property($fn, "nopush");

	pidl $static . "NTSTATUS ndr_push_$fn->{NAME}(struct ndr_push *ndr, int flags, struct $fn->{NAME} *r)";
	pidl "{";
	indent;

	pidl "if (!(flags & NDR_IN)) goto ndr_out;";
	pidl "";

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "in")) {
			if (util::has_property($e, "ref")) {
				check_null_pointer("*r->in.$e->{NAME}");
			} 
			ParseFunctionElementPush($e, "in");
		}		
	}

	pidl "ndr_out:";
	pidl "if (!(flags & NDR_OUT)) goto done;";
	pidl "";

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "out")) {
			if (util::has_property($e, "ref")) {
				check_null_pointer("*r->out.$e->{NAME}");
			} 
			ParseFunctionElementPush($e, "out");
		}		
	}

	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		pidl "NDR_CHECK(ndr_push_$fn->{RETURN_TYPE}(ndr, NDR_SCALARS, r->out.result));";
	}
    
	pidl "done:";
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# parse a function element
sub ParseFunctionElementPull($$)
{ 
	my $e = shift;
	my $inout = shift;

	if (util::array_size($e)) {
		if (Ndr::need_wire_pointer($e)) {
			pidl "NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_$e->{NAME}));";
			pidl "r->$inout.$e->{NAME} = NULL;";
			pidl "if (_ptr_$e->{NAME}) {";
			indent;
		} elsif ($inout eq "out" && util::has_property($e, "ref")) {
			pidl "if (r->$inout.$e->{NAME}) {";
			indent;
		}

		ParseArrayPull($e, "ndr", "r->$inout.", "NDR_SCALARS|NDR_BUFFERS");

		if (Ndr::need_wire_pointer($e) or ($inout eq "out" and util::has_property($e, "ref"))) {
			deindent;
			pidl "}";
		}
	} else {
		if ($inout eq "out" && util::has_property($e, "ref")) {
			pidl "if (ndr->flags & LIBNDR_FLAG_REF_ALLOC) {";
			pidl "\tNDR_ALLOC(ndr, r->out.$e->{NAME});";
			pidl "}";
		}

		if ($inout eq "in" && util::has_property($e, "ref")) {
			pidl "NDR_ALLOC(ndr, r->in.$e->{NAME});";
		}

		ParseElementPullScalar($e, "r->$inout.", "NDR_SCALARS|NDR_BUFFERS");
		if (Ndr::need_wire_pointer($e)) {
			ParseElementPullBuffer($e, "r->$inout.");
		}
	}
}

############################################################
# allocate ref variables
sub AllocateRefVars($)
{
	my $e = shift;
	my $asize = util::array_size($e);

	# note that if the variable is also an "in"
	# variable then we copy the initial value from
	# the in side

	if (!defined $asize) {
		# its a simple variable
		pidl "NDR_ALLOC(ndr, r->out.$e->{NAME});";
		if (util::has_property($e, "in")) {
			pidl "*r->out.$e->{NAME} = *r->in.$e->{NAME};";
		} else {
			pidl "ZERO_STRUCTP(r->out.$e->{NAME});";
		}
		return;
	}

	# its an array
	my $size = ParseExpr($e, $asize, "r->out.");
	check_null_pointer($size);
	pidl "NDR_ALLOC_N(ndr, r->out.$e->{NAME}, $size);";
	if (util::has_property($e, "in")) {
		pidl "memcpy(r->out.$e->{NAME},r->in.$e->{NAME},$size * sizeof(*r->in.$e->{NAME}));";
	} else {
		pidl "memset(r->out.$e->{NAME}, 0, $size * sizeof(*r->out.$e->{NAME}));";
	}
}

#####################################################################
# parse a function
sub ParseFunctionPull($)
{ 
	my($fn) = shift;
	my $static = fn_prefix($fn);

	return unless !util::has_property($fn, "nopull");

	# pull function args
	pidl $static . "NTSTATUS ndr_pull_$fn->{NAME}(struct ndr_pull *ndr, int flags, struct $fn->{NAME} *r)";
	pidl "{";
	indent;

	# declare any internal pointers we need
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (Ndr::need_wire_pointer($e)) {
			pidl "uint32_t _ptr_$e->{NAME};";
		}
	}

	pidl "if (!(flags & NDR_IN)) goto ndr_out;";
	pidl "";

	# auto-init the out section of a structure. I originally argued that
	# this was a bad idea as it hides bugs, but coping correctly
	# with initialisation and not wiping ref vars is turning
	# out to be too tricky (tridge)
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "out")) {
			pidl "ZERO_STRUCT(r->out);";
			pidl "";
			last;
		}
	}

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "in")) {
			ParseFunctionElementPull($e, "in");
		}
		# we need to allocate any reference output variables, so that
		# a dcerpc backend can be sure they are non-null
		if (util::has_property($e, "out") && util::has_property($e, "ref")) {
			AllocateRefVars($e);
		}
	}

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "in")) {
			CheckArraySizes($e, "r->in.");
		}
	}

	pidl "ndr_out:";
	pidl "if (!(flags & NDR_OUT)) goto done;";
	pidl "";

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "out")) {
			ParseFunctionElementPull($e, "out");
		}
	}

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (util::has_property($e, "out")) {
			CheckArraySizes($e, "r->out.");
		}
	}

	if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
		pidl "NDR_CHECK(ndr_pull_$fn->{RETURN_TYPE}(ndr, NDR_SCALARS, &r->out.result));";
	}

	pidl "done:";
	pidl "";
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# produce a function call table
sub FunctionTable($)
{
	my($interface) = shift;
	my($data) = $interface->{INHERITED_DATA};
	my $count = 0;
	my $uname = uc $interface->{NAME};

	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") { $count++; }
	}

	return if ($count == 0);

	pidl "static const struct dcerpc_interface_call $interface->{NAME}\_calls[] = {";
	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") {
			pidl "\t{";
			pidl "\t\t\"$d->{NAME}\",";
			pidl "\t\tsizeof(struct $d->{NAME}),";
			pidl "\t\t(ndr_push_flags_fn_t) ndr_push_$d->{NAME},";
			pidl "\t\t(ndr_pull_flags_fn_t) ndr_pull_$d->{NAME},";
			pidl "\t\t(ndr_print_function_t) ndr_print_$d->{NAME}";
			pidl "\t},";
		}
	}
	pidl "\t{ NULL, 0, NULL, NULL, NULL }";
	pidl "};";
	pidl "";

	# If no endpoint is set, default to the interface name as a named pipe
	if (! defined $interface->{PROPERTIES}->{endpoint}) {
		$interface->{PROPERTIES}->{endpoint} = "\"ncacn_np:[\\\\pipe\\\\" . $interface->{NAME} . "]\"";
	}

	my @e = split / /, $interface->{PROPERTIES}->{endpoint};
	my $endpoint_count = $#e + 1;

	pidl "static const char * const $interface->{NAME}\_endpoint_strings[] = {";
	foreach my $ep (@e) {
		pidl "\t$ep, ";
	}
	pidl "};";
	pidl "";

	pidl "static const struct dcerpc_endpoint_list $interface->{NAME}\_endpoints = {";
	pidl "\t.count\t= $endpoint_count,";
	pidl "\t.names\t= $interface->{NAME}\_endpoint_strings";
	pidl "};";
	pidl "";

	if (! defined $interface->{PROPERTIES}->{authservice}) {
		$interface->{PROPERTIES}->{authservice} = "\"host\"";
	}

	my @a = split / /, $interface->{PROPERTIES}->{authservice};
	my $authservice_count = $#a + 1;

	pidl "static const char * const $interface->{NAME}\_authservice_strings[] = {";
	foreach my $ap (@a) {
		pidl "\t$ap, ";
	}
	pidl "};";
	pidl "";

	pidl "static const struct dcerpc_authservice_list $interface->{NAME}\_authservices = {";
	pidl "\t.count\t= $endpoint_count,";
	pidl "\t.names\t= $interface->{NAME}\_authservice_strings";
	pidl "};";
	pidl "";

	pidl "\nconst struct dcerpc_interface_table dcerpc_table_$interface->{NAME} = {";
	pidl "\t.name\t\t= \"$interface->{NAME}\",";
	pidl "\t.uuid\t\t= DCERPC_$uname\_UUID,";
	pidl "\t.if_version\t= DCERPC_$uname\_VERSION,";
	pidl "\t.helpstring\t= DCERPC_$uname\_HELPSTRING,";
	pidl "\t.num_calls\t= $count,";
	pidl "\t.calls\t\t= $interface->{NAME}\_calls,";
	pidl "\t.endpoints\t= &$interface->{NAME}\_endpoints,";
	pidl "\t.authservices\t= &$interface->{NAME}\_authservices";
	pidl "};";
	pidl "";

	pidl "static NTSTATUS dcerpc_ndr_$interface->{NAME}_init(void)";
	pidl "{";
	pidl "\treturn librpc_register_interface(&dcerpc_table_$interface->{NAME});";
	pidl "}";
	pidl "";
}

#####################################################################
# parse the interface definitions
sub ParseInterface($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};

	# Push functions
	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "TYPEDEF") {
		    ParseTypedefPush($d);
		    ParseTypedefPull($d);
			ParseTypedefPrint($d);
			ParseTypedefNdrSize($d);
		}
	}

	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") {
		    ParseFunctionPush($d);
		    ParseFunctionPull($d);
			ParseFunctionPrint($d);
		}
	}

	FunctionTable($interface);
}

sub RegistrationFunction($$)
{
	my $idl = shift;
	my $filename = shift;

	$filename =~ /.*\/ndr_(.*).c/;
	my $basename = $1;
	pidl "NTSTATUS dcerpc_$basename\_init(void)";
	pidl "{";
	indent;
	pidl "NTSTATUS status = NT_STATUS_OK;";
	foreach my $interface (@{$idl}) {
		next if $interface->{TYPE} ne "INTERFACE";

		my $data = $interface->{INHERITED_DATA};
		my $count = 0;
		foreach my $d (@{$data}) {
			if ($d->{TYPE} eq "FUNCTION") { $count++; }
		}

		next if ($count == 0);

		pidl "status = dcerpc_ndr_$interface->{NAME}_init();";
		pidl "if (NT_STATUS_IS_ERR(status)) {";
		pidl "\treturn status;";
		pidl "}";
		pidl "";
	}
	pidl "return status;";
	deindent;
	pidl "}";
	pidl "";
}

sub CheckPointerTypes($$)
{
	my $s = shift;
	my $default = shift;

	foreach my $e (@{$s->{ELEMENTS}}) {
		if ($e->{POINTERS}) {
			if (not defined(Ndr::pointer_type($e))) {
				$e->{PROPERTIES}->{$default} = 1;
			}

			if (Ndr::pointer_type($e) eq "ptr") {
				print "Warning: ptr is not supported by pidl yet\n";
			}
		}
	}
}

sub LoadInterface($)
{
	my $x = shift;

	if (not util::has_property($x, "pointer_default")) {
		# MIDL defaults to "ptr" in DCE compatible mode (/osf)
		# and "unique" in Microsoft Extensions mode (default)
		$x->{PROPERTIES}->{pointer_default} = "unique";
	}

	foreach my $d (@{$x->{DATA}}) {
		if (($d->{TYPE} eq "DECLARE") or ($d->{TYPE} eq "TYPEDEF")) {
			if ($d->{DATA}->{TYPE} eq "STRUCT" or $d->{DATA}->{TYPE} eq "UNION") {
				CheckPointerTypes($d->{DATA}, $x->{PROPERTIES}->{pointer_default});
			}

			if (defined($d->{PROPERTIES}) && !defined($d->{DATA}->{PROPERTIES})) {
				$d->{DATA}->{PROPERTIES} = $d->{PROPERTIES};
			}
		}
		if ($d->{TYPE} eq "FUNCTION") {
			CheckPointerTypes($d, 
				$x->{PROPERTIES}->{pointer_default}  # MIDL defaults to "ref"
			);
		}
	}
}

sub Load($)
{
	my $idl = shift;

	foreach my $x (@{$idl}) {
		LoadInterface($x);
	}
}

#####################################################################
# parse a parsed IDL structure back into an IDL file
sub Parse($$)
{
	my($idl) = shift;
	my($filename) = shift;
	my $h_filename = $filename;
	$res = "";

	Load($idl);

	if ($h_filename =~ /(.*)\.c/) {
		$h_filename = "$1.h";
	}

	pidl "/* parser auto-generated by pidl */";
	pidl "";
	pidl "#include \"includes.h\"";
	pidl "#include \"$h_filename\"";
	pidl "";

	foreach my $x (@{$idl}) {
		if ($x->{TYPE} eq "INTERFACE") { 
			needed::BuildNeeded($x);
			ParseInterface($x);
		}
	}

	RegistrationFunction($idl, $filename);

	return $res;
}

1;
