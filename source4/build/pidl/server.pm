###################################################
# server boilerplate generator
# Copyright tridge@samba.org 2003
# Copyright metze@samba.org 2004
# released under the GNU GPL

package IdlServer;

use strict;

my($res);

sub pidl($)
{
	$res .= shift;
}


#####################################################
# generate the switch statement for function dispatch
sub gen_dispatch_switch($)
{
	my $data = shift;

	my $count = 0;
	foreach my $d (@{$data}) {
		next if ($d->{TYPE} ne "FUNCTION");

		pidl "\tcase $count: {\n";
		pidl "\t\tstruct $d->{NAME} *r2 = r;\n";
		pidl "\t\tif (DEBUGLEVEL > 10) {\n";
		pidl "\t\t\tNDR_PRINT_FUNCTION_DEBUG($d->{NAME}, NDR_IN, r2);\n";
		pidl "\t\t}\n";
		if ($d->{RETURN_TYPE} && $d->{RETURN_TYPE} ne "void") {
			pidl "\t\tr2->out.result = $d->{NAME}(dce_call, mem_ctx, r2);\n";
		} else {
			pidl "\t\t$d->{NAME}(dce_call, mem_ctx, r2);\n";
		}
		pidl "\t\tif (DEBUGLEVEL > 10 && dce_call->fault_code == 0) {\n";
		pidl "\t\t\tNDR_PRINT_FUNCTION_DEBUG($d->{NAME}, NDR_OUT | NDR_SET_VALUES, r2);\n";
		pidl "\t\t}\n";
		pidl "\t\tif (dce_call->fault_code != 0) {\n";
		pidl "\t\t\tDEBUG(2,(\"dcerpc_fault %s in $d->{NAME}\\n\", dcerpc_errstr(mem_ctx, dce_call->fault_code)));\n";
		pidl "\t\t}\n";
		pidl "\t\tbreak;\n\t}\n";
		$count++; 
	}
}


#####################################################################
# produce boilerplate code for a interface
sub Boilerplate_Iface($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};
	my $name = $interface->{NAME};
	my $uname = uc $name;
	my $uuid = util::make_str($interface->{PROPERTIES}->{uuid});
	my $if_version = $interface->{PROPERTIES}->{version};

	pidl "
static NTSTATUS $name\__op_bind(struct dcesrv_call_state *dce_call, const struct dcesrv_interface *iface)
{
#ifdef DCESRV_INTERFACE_$uname\_BIND
	return DCESRV_INTERFACE_$uname\_BIND(dce_call,iface);
#else
	return NT_STATUS_OK;
#endif
}

static void $name\__op_unbind(struct dcesrv_connection *dce_conn, const struct dcesrv_interface *iface)
{
#ifdef DCESRV_INTERFACE_$uname\_UNBIND
	DCESRV_INTERFACE_$uname\_UNBIND(dce_conn,iface);
#else
	return;
#endif
}

static NTSTATUS $name\__op_ndr_pull(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_pull *pull, void **r)
{
	NTSTATUS status;
	uint16 opnum = dce_call->pkt.u.request.opnum;

	dce_call->fault_code = 0;

	if (opnum >= dcerpc_table_$name.num_calls) {
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	*r = talloc(mem_ctx, dcerpc_table_$name.calls[opnum].struct_size);
	if (!*r) {
		return NT_STATUS_NO_MEMORY;
	}

        /* unravel the NDR for the packet */
	status = dcerpc_table_$name.calls[opnum].ndr_pull(pull, NDR_IN, *r);
	if (!NT_STATUS_IS_OK(status)) {
		dcerpc_log_packet(&dcerpc_table_$name, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS $name\__op_dispatch(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16 opnum = dce_call->pkt.u.request.opnum;

	dce_call->fault_code = 0;

	switch (opnum) {
";
	gen_dispatch_switch($data);

pidl "
	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS $name\__op_ndr_push(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_push *push, void *r)
{
	NTSTATUS status;
	uint16 opnum = dce_call->pkt.u.request.opnum;

	status = dcerpc_table_$name.calls[opnum].ndr_push(push, NDR_OUT, r);
	if (!NT_STATUS_IS_OK(status)) {
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static const struct dcesrv_interface $name\_interface = {
	\"$name\",
	$uuid,
	$if_version,
	$name\__op_bind,
	$name\__op_unbind,
	$name\__op_ndr_pull,
	$name\__op_dispatch,
	$name\__op_ndr_push
};

";
}

#####################################################################
# produce boilerplate code for an endpoint server
sub Boilerplate_Ep_Server($)
{
	my($interface) = shift;
	my $name = $interface->{NAME};
	my $uname = uc $name;

	pidl "
static NTSTATUS $name\__op_init_server(struct dcesrv_context *dce_ctx, const struct dcesrv_endpoint_server *ep_server)
{
	int i;

	for (i=0;i<dcerpc_table_$name.endpoints->count;i++) {
		NTSTATUS ret;
		const char *name = dcerpc_table_$name.endpoints->names[i];

		ret = dcesrv_interface_register(dce_ctx, name, &$name\_interface, NULL);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1,(\"$name\_op_init_server: failed to register endpoint \'%s\'\\n\",name));
			return ret;
		}
	}

	return NT_STATUS_OK;
}

static BOOL $name\__op_interface_by_uuid(struct dcesrv_interface *iface, const char *uuid, uint32 if_version)
{
	if ($name\_interface.if_version == if_version &&
		strcmp($name\_interface.uuid, uuid)==0) {
		memcpy(iface,&$name\_interface, sizeof(*iface));
		return True;
	}

	return False;
}

static BOOL $name\__op_interface_by_name(struct dcesrv_interface *iface, const char *name)
{
	if (strcmp($name\_interface.name, name)==0) {
		memcpy(iface,&$name\_interface, sizeof(*iface));
		return True;
	}

	return False;	
}
	
NTSTATUS dcerpc_server_$name\_init(void)
{
	NTSTATUS ret;
	struct dcesrv_endpoint_server ep_server;

	/* fill in our name */
	ep_server.name = \"$name\";

	/* fill in all the operations */
	ep_server.init_server = $name\__op_init_server;

	ep_server.interface_by_uuid = $name\__op_interface_by_uuid;
	ep_server.interface_by_name = $name\__op_interface_by_name;

	/* register ourselves with the DCERPC subsystem. */
	ret = dcerpc_register_ep_server(&ep_server);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,(\"Failed to register \'$name\' endpoint server!\\n\"));
		return ret;
	}

	return ret;
}

";
}

#####################################################################
# parse a parsed IDL structure back into an IDL file
sub ParseInterface($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};
	my $count = 0;

	$res = "";

	if (!defined $interface->{PROPERTIES}->{uuid}) {
		return $res;
	}

	if (!defined $interface->{PROPERTIES}->{version}) {
		$interface->{PROPERTIES}->{version} = "0.0";
	}

	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") { $count++; }
	}

	if ($count == 0) {
		return $res;
	}

	$res = "/* dcerpc server boilerplate generated by pidl */\n\n";
	Boilerplate_Iface($interface);
	Boilerplate_Ep_Server($interface);

	return $res;
}

1;

