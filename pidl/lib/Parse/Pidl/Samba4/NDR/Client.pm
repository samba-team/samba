###################################################
# client calls generator
# Copyright tridge@samba.org 2003
# Copyright jelmer@samba.org 2005-2006
# released under the GNU GPL

package Parse::Pidl::Samba4::NDR::Client;

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(Parse);

use Parse::Pidl::Samba4 qw(choose_header is_intree);
use Parse::Pidl::Util qw(has_property);

use vars qw($VERSION);
$VERSION = '0.01';

use strict;

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

sub ParseFunction_r_State($$$$)
{
	my ($self, $if, $fn, $name) = @_;
	my $uname = uc $name;

	$self->pidl("struct dcerpc_$name\_r_state {");
	$self->indent;
	$self->pidl("TALLOC_CTX *out_mem_ctx;");
	$self->deindent;
	$self->pidl("};");
	$self->pidl("");
	$self->pidl("static void dcerpc_$name\_r_done(struct tevent_req *subreq);");
	$self->pidl("");
}

sub ParseFunction_r_Send($$$$)
{
	my ($self, $if, $fn, $name) = @_;
	my $uname = uc $name;

	my $proto = "struct tevent_req *dcerpc_$name\_r_send(TALLOC_CTX *mem_ctx,\n";
	$proto   .= "\tstruct tevent_context *ev,\n",
	$proto   .= "\tstruct dcerpc_binding_handle *h,\n",
	$proto   .= "\tstruct $name *r)";

	$self->fn_declare($proto);

	$self->pidl("{");
	$self->indent;

	$self->pidl("struct tevent_req *req;");
	$self->pidl("struct dcerpc_$name\_r_state *state;");
	$self->pidl("struct tevent_req *subreq;");
	$self->pidl("");

	$self->pidl("req = tevent_req_create(mem_ctx, &state,");
	$self->pidl("\t\t\tstruct dcerpc_$name\_r_state);");
	$self->pidl("if (req == NULL) {");
	$self->indent;
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	my $out_params = 0;
	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/out/, @{$_->{DIRECTION}})) {
			$out_params++;
		}
	}

	my $submem;
	if ($out_params > 0) {
		$self->pidl("state->out_mem_ctx = talloc_new(state);");
		$self->pidl("if (tevent_req_nomem(state->out_mem_ctx, req)) {");
		$self->indent;
		$self->pidl("return tevent_req_post(req, ev);");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");
		$submem = "state->out_mem_ctx";
	} else {
		$self->pidl("state->out_mem_ctx = NULL;");
		$submem = "state";
	}

	$self->pidl("subreq = dcerpc_binding_handle_call_send(state, ev, h,");
	$self->pidl("\t\tNULL, &ndr_table_$if->{NAME},");
	$self->pidl("\t\tNDR_$uname, $submem, r);");
	$self->pidl("if (tevent_req_nomem(subreq, req)) {");
	$self->indent;
	$self->pidl("return tevent_req_post(req, ev);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("tevent_req_set_callback(subreq, dcerpc_$name\_r_done, req);");
	$self->pidl("");

	$self->pidl("return req;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseFunction_r_Done($$$$)
{
	my ($self, $if, $fn, $name) = @_;
	my $uname = uc $name;

	my $proto = "static void dcerpc_$name\_r_done(struct tevent_req *subreq)";

	$self->pidl("$proto");
	$self->pidl("{");
	$self->indent;

	$self->pidl("struct tevent_req *req =");
	$self->pidl("\ttevent_req_callback_data(subreq,");
	$self->pidl("\tstruct tevent_req);");
	$self->pidl("NTSTATUS status;");
	$self->pidl("");

	$self->pidl("status = dcerpc_binding_handle_call_recv(subreq);");
	$self->pidl("if (!NT_STATUS_IS_OK(status)) {");
	$self->indent;
	$self->pidl("tevent_req_nterror(req, status);");
	$self->pidl("return;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("tevent_req_done(req);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseFunction_r_Recv($$$$)
{
	my ($if, $fn, $name) = @_;
	my ($self, $if, $fn, $name) = @_;
	my $uname = uc $name;

	my $proto = "NTSTATUS dcerpc_$name\_r_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx)";

	$self->fn_declare($proto);

	$self->pidl("{");
	$self->indent;

	$self->pidl("struct dcerpc_$name\_r_state *state =");
	$self->pidl("\ttevent_req_data(req,");
	$self->pidl("\tstruct dcerpc_$name\_r_state);");
	$self->pidl("NTSTATUS status;");
	$self->pidl("");

	$self->pidl("if (tevent_req_is_nterror(req, &status)) {");
	$self->indent;
	$self->pidl("tevent_req_received(req);");
	$self->pidl("return status;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("talloc_steal(mem_ctx, state->out_mem_ctx);");
	$self->pidl("");

	$self->pidl("tevent_req_received(req);");
	$self->pidl("return NT_STATUS_OK;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseFunction_r_Sync($$$$)
{
	my ($if, $fn, $name) = @_;
	my ($self, $if, $fn, $name) = @_;
	my $uname = uc $name;

	my $proto = "NTSTATUS dcerpc_$name\_r(struct dcerpc_binding_handle *h, TALLOC_CTX *mem_ctx, struct $name *r)";

	$self->fn_declare($proto);

	$self->pidl("{");
	$self->indent;
	$self->pidl("NTSTATUS status;");
	$self->pidl("");

	$self->pidl("status = dcerpc_binding_handle_call(h,");
	$self->pidl("\t\tNULL, &ndr_table_$if->{NAME},");
	$self->pidl("\t\tNDR_$uname, mem_ctx, r);");
	$self->pidl("");
	$self->pidl("return status;");

	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

#####################################################################
# parse a function
sub ParseFunction($$$)
{
	my ($self, $if, $fn) = @_;

	$self->ParseFunction_r_State($if, $fn, $fn->{NAME});
	$self->ParseFunction_r_Send($if, $fn, $fn->{NAME});
	$self->ParseFunction_r_Done($if, $fn, $fn->{NAME});
	$self->ParseFunction_r_Recv($if, $fn, $fn->{NAME});
	$self->ParseFunction_r_Sync($if, $fn, $fn->{NAME});

	$self->pidl_hdr("");
}

my %done;

#####################################################################
# parse the interface definitions
sub ParseInterface($$)
{
	my ($self, $if) = @_;

	$self->pidl_hdr("#ifndef _HEADER_RPC_$if->{NAME}");
	$self->pidl_hdr("#define _HEADER_RPC_$if->{NAME}");
	$self->pidl_hdr("");

	if (defined $if->{PROPERTIES}->{uuid}) {
		$self->pidl_hdr("extern const struct ndr_interface_table ndr_table_$if->{NAME};");
		$self->pidl_hdr("");
	}

	$self->pidl("/* $if->{NAME} - client functions generated by pidl */");
	$self->pidl("");

	foreach my $fn (@{$if->{FUNCTIONS}}) {
		next if defined($done{$fn->{NAME}});
		next if has_property($fn, "noopnum");
		next if has_property($fn, "todo");
		$self->ParseFunction($if, $fn);
		$done{$fn->{NAME}} = 1;
	}

	$self->pidl_hdr("#endif /* _HEADER_RPC_$if->{NAME} */");
}

sub Parse($$$$$$)
{
	my($self,$ndr,$header,$ndr_header,$client_header) = @_;

	$self->pidl("/* client functions auto-generated by pidl */");
	$self->pidl("");
	if (is_intree()) {
		$self->pidl("#include \"includes.h\"");
	} else {
		$self->pidl("#ifndef _GNU_SOURCE");
		$self->pidl("#define _GNU_SOURCE");
		$self->pidl("#endif");
		$self->pidl("#include <stdio.h>");
		$self->pidl("#include <stdbool.h>");
		$self->pidl("#include <stdlib.h>");
		$self->pidl("#include <stdint.h>");
		$self->pidl("#include <stdarg.h>");
		$self->pidl("#include <core/ntstatus.h>");
	}
	$self->pidl("#include <tevent.h>");
	$self->pidl(choose_header("lib/util/tevent_ntstatus.h", "util/tevent_ntstatus.h")."");
	$self->pidl("#include \"$ndr_header\"");
	$self->pidl("#include \"$client_header\"");
	$self->pidl("");

	$self->pidl_hdr(choose_header("librpc/rpc/dcerpc.h", "dcerpc.h")."");
	$self->pidl_hdr("#include \"$header\"");

	foreach my $x (@{$ndr}) {
		($x->{TYPE} eq "INTERFACE") && $self->ParseInterface($x);
	}

	return ($self->{res},$self->{res_hdr});
}

1;
