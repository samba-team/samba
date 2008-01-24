###################################################
# Samba3 libnetapi generator for IDL structures
# on top of Samba4 style NDR functions
# Copyright jelmer@samba.org 2005-2006
# Copyright gd@samba.org 2008
# released under the GNU GPL

package Parse::Pidl::Samba3::libnetapi;

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(ParseFunction $res $res_hdr);

use strict;
use Parse::Pidl qw(fatal warning);
use Parse::Pidl::Typelist qw(hasType getType mapTypeName scalar_is_reference);
use Parse::Pidl::Util qw(has_property is_constant ParseExpr);
use Parse::Pidl::NDR qw(GetPrevLevel GetNextLevel ContainsDeferred);
use Parse::Pidl::Samba4 qw(DeclLong);
use Parse::Pidl::Samba4::Header qw(GenerateFunctionInEnv);

use vars qw($VERSION);
$VERSION = '0.01';

sub indent($) { my ($self) = @_; $self->{tabs}.="\t"; }
sub deindent($) { my ($self) = @_; $self->{tabs} = substr($self->{tabs}, 1); }
sub pidl($$) { my ($self,$txt) = @_; $self->{res} .= $txt ? "$self->{tabs}$txt\n" : "\n"; }
sub pidl_hdr($$) { my ($self, $txt) = @_; $self->{res_hdr} .= "$txt\n"; }
sub fn_declare($$) { my ($self,$n) = @_; $self->pidl($n); $self->pidl_hdr("$n;"); }

sub genpad($)
{
	my ($s) = @_;
	my $nt = int((length($s)+1)/8);
	my $lt = ($nt*8)-1;
	my $ns = (length($s)-$lt);
	return "\t"x($nt)." "x($ns);
}

sub new($)
{
	my ($class) = shift;
	my $self = { res => "", res_hdr => "", tabs => "" };
	bless($self, $class);
}

sub ParseFunction($$$)
{
	my ($self, $if, $fn) = @_;

	my $fn_args = "";
	my $fn_args2 = "ctx";
	my $uif = uc($if);
	my $ufn = "NDR_".uc($fn->{NAME});
	my $fn_str = "NET_API_STATUS $fn->{NAME}";
#	my $fn_str2 = "werr = libnetapi_$fn->{NAME}";
	my $fn_str_l = "werr = $fn->{NAME}_l";
	my $fn_str_r = "werr = $fn->{NAME}_r";
	my $pad = genpad($fn_str);
#	my $pad2 = genpad(" "x(8).$fn_str2);
	my $pad2 = genpad(" "x(16).$fn_str_l);

	foreach (@{$fn->{ELEMENTS}}) {
		$fn_args .= ($fn_args eq "") ? DeclLong($_):",\n".$pad.DeclLong($_);
	}

	foreach (@{$fn->{ELEMENTS}}) {
		$fn_args2 .= ",\n" . $pad2 . $_->{NAME};
	}

	$self->pidl("/****************************************************************");
	$self->pidl(" $fn->{NAME}");
	$self->pidl("****************************************************************/");
	$self->pidl("");
	$self->fn_declare("$fn_str($fn_args)");
	$self->pidl_hdr("WERROR $fn->{NAME}_r(struct libnetapi_ctx *ctx,\n$pad$fn_args);");
	$self->pidl_hdr("WERROR $fn->{NAME}_l(struct libnetapi_ctx *ctx,\n$pad$fn_args);");
	$self->pidl("{");
	$self->indent;
	$self->pidl("struct libnetapi_ctx *ctx = NULL;");
	$self->pidl("NET_API_STATUS status;");
	$self->pidl("WERROR werr;");
	$self->pidl("");

	$self->pidl("status = libnetapi_getctx(&ctx);");
	$self->pidl("if (status != 0) {");
	$self->indent;
	$self->pidl("return status;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

#	$self->pidl("$fn_str2($fn_args2);");
	$self->pidl("if (LIBNETAPI_LOCAL_SERVER($fn->{ELEMENTS}[0]->{NAME})) {");
	$self->indent;
	$self->pidl("$fn_str_l($fn_args2);");
	$self->deindent;
	$self->pidl("} else {");
	$self->indent;
	$self->pidl("$fn_str_r($fn_args2);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("if (!W_ERROR_IS_OK(werr)) {");
	$self->indent;
	$self->pidl("return W_ERROR_V(werr);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("return NET_API_STATUS_SUCCESS;");
=cut
	$self->pidl("NTSTATUS status;");
	$self->pidl("");
	$self->pidl("/* In parameters */");

	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/in/, @{$_->{DIRECTION}})) {
			$self->pidl("r.in.$_->{NAME} = $_->{NAME};");
		}
	}

	$self->pidl("");
	$self->pidl("if (DEBUGLEVEL >= 10) {");
	$self->indent;
	$self->pidl("NDR_PRINT_IN_DEBUG($fn->{NAME}, &r);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("status = cli_do_rpc_ndr(cli,");
	$self->pidl("\t\t\tmem_ctx,");
	$self->pidl("\t\t\tPI_$uif,");
	$self->pidl("\t\t\t&ndr_table_$if,");
	$self->pidl("\t\t\t$ufn,");
	$self->pidl("\t\t\t&r);");
	$self->pidl("");

	$self->pidl("if (!NT_STATUS_IS_OK(status)) {");
	$self->indent;
	$self->pidl("return status;");
	$self->deindent;
	$self->pidl("}");

	$self->pidl("");
	$self->pidl("if (DEBUGLEVEL >= 10) {");
	$self->indent;
	$self->pidl("NDR_PRINT_OUT_DEBUG($fn->{NAME}, &r);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("if (NT_STATUS_IS_ERR(status)) {");
	$self->indent;
	$self->pidl("return status;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("/* Return variables */");
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep(/out/, @{$e->{DIRECTION}}));
		my $level = 0;

		fatal($e->{ORIGINAL}, "[out] argument is not a pointer or array") if ($e->{LEVELS}[0]->{TYPE} ne "POINTER" and $e->{LEVELS}[0]->{TYPE} ne "ARRAY");

		if ($e->{LEVELS}[0]->{TYPE} eq "POINTER") {
			$level = 1;
			if ($e->{LEVELS}[0]->{POINTER_TYPE} ne "ref") {
				$self->pidl("if ($e->{NAME} && r.out.$e->{NAME}) {");
				$self->indent;
			}
		}

		if ($e->{LEVELS}[$level]->{TYPE} eq "ARRAY") {
			# This is a call to GenerateFunctionInEnv intentionally. 
			# Since the data is being copied into a user-provided data 
			# structure, the user should be able to know the size beforehand 
			# to allocate a structure of the right size.
			my $env = GenerateFunctionInEnv($fn, "r.");
			my $size_is = ParseExpr($e->{LEVELS}[$level]->{SIZE_IS}, $env, $e->{ORIGINAL});
			$self->pidl("memcpy($e->{NAME}, r.out.$e->{NAME}, $size_is);");
		} else {
			$self->pidl("*$e->{NAME} = *r.out.$e->{NAME};");
		}

		if ($e->{LEVELS}[0]->{TYPE} eq "POINTER") {
			if ($e->{LEVELS}[0]->{POINTER_TYPE} ne "ref") {
				$self->deindent;
				$self->pidl("}");
			}
		}
	}

	$self->pidl("");
	$self->pidl("/* Return result */");
	if (not $fn->{RETURN_TYPE}) {
		$self->pidl("return NET_API_STATUS_SUCCESS;");
	} elsif ($fn->{RETURN_TYPE} eq "NET_API_STATUS") {
		$self->pidl("return r.out.result;");
	} elsif ($fn->{RETURN_TYPE} eq "WERROR") {
		$self->pidl("if (werror) {");
		$self->indent;
		$self->pidl("*werror = r.out.result;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");
		$self->pidl("return werror_to_ntstatus(r.out.result);");
	} else {
		warning($fn->{ORIGINAL}, "Unable to convert $fn->{RETURN_TYPE} to NTSTATUS");
		$self->pidl("return NT_STATUS_OK;");
	}
=cut
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseInterface($$)
{
	my ($self, $if) = @_;

	my $uif = uc($if->{NAME});

	$self->pidl_hdr("#ifndef __LIBNETAPI_$uif\__");
	$self->pidl_hdr("#define __LIBNETAPI_$uif\__");
	$self->ParseFunction($if->{NAME}, $_) foreach (@{$if->{FUNCTIONS}});
	$self->pidl_hdr("#endif /* __LIBNETAPI_$uif\__ */");
}

sub Parse($$$$)
{
	my($self,$ndr,$header,$ndr_header) = @_;

	$self->pidl("/*");
	$self->pidl(" * Unix SMB/CIFS implementation.");
	$self->pidl(" * libnetapi auto-generated by pidl. DO NOT MODIFY!");
	$self->pidl(" */");
	$self->pidl("");
	$self->pidl("#include \"includes.h\"");
	$self->pidl("#include \"lib/netapi/netapi.h\"");
	$self->pidl("#include \"$header\"");
#	$self->pidl_hdr("#include \"$ndr_header\"");
	$self->pidl("");

	foreach (@$ndr) {
		$self->ParseInterface($_) if ($_->{TYPE} eq "INTERFACE");
	}

	return ($self->{res}, $self->{res_hdr});
}

1;
