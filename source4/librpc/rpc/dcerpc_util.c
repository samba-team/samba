/* 
   Unix SMB/CIFS implementation.

   dcerpc utility functions

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Jelmer Vernooij 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "libcli/composite/composite.h"
#include "librpc/gen_ndr/ndr_epmapper.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "librpc/gen_ndr/ndr_misc.h"

/*
  find a dcerpc call on an interface by name
*/
const struct dcerpc_interface_call *dcerpc_iface_find_call(const struct dcerpc_interface_table *iface,
							   const char *name)
{
	int i;
	for (i=0;i<iface->num_calls;i++) {
		if (strcmp(iface->calls[i].name, name) == 0) {
			return &iface->calls[i];
		}
	}
	return NULL;
}

/* 
   push a ncacn_packet into a blob, potentially with auth info
*/
NTSTATUS ncacn_push_auth(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, 
			  struct ncacn_packet *pkt,
			  struct dcerpc_auth *auth_info)
{
	NTSTATUS status;
	struct ndr_push *ndr;

	ndr = ndr_push_init_ctx(mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!(pkt->drep[0] & DCERPC_DREP_LE)) {
		ndr->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	if (pkt->pfc_flags & DCERPC_PFC_FLAG_ORPC) {
		ndr->flags |= LIBNDR_FLAG_OBJECT_PRESENT;
	}

	if (auth_info) {
		pkt->auth_length = auth_info->credentials.length;
	} else {
		pkt->auth_length = 0;
	}

	status = ndr_push_ncacn_packet(ndr, NDR_SCALARS|NDR_BUFFERS, pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (auth_info) {
		status = ndr_push_dcerpc_auth(ndr, NDR_SCALARS|NDR_BUFFERS, auth_info);
	}

	*blob = ndr_push_blob(ndr);

	/* fill in the frag length */
	dcerpc_set_frag_length(blob, blob->length);

	return NT_STATUS_OK;
}

#define MAX_PROTSEQ		10

static const struct {
	const char *name;
	enum dcerpc_transport_t transport;
	int num_protocols;
	enum epm_protocol protseq[MAX_PROTSEQ];
} transports[] = {
	{ "ncacn_np",     NCACN_NP, 3, 
		{ EPM_PROTOCOL_NCACN, EPM_PROTOCOL_SMB, EPM_PROTOCOL_NETBIOS }},
	{ "ncacn_ip_tcp", NCACN_IP_TCP, 3, 
		{ EPM_PROTOCOL_NCACN, EPM_PROTOCOL_TCP, EPM_PROTOCOL_IP } }, 
	{ "ncacn_http", NCACN_HTTP, 3, 
		{ EPM_PROTOCOL_NCACN, EPM_PROTOCOL_HTTP, EPM_PROTOCOL_IP } }, 
	{ "ncadg_ip_udp", NCACN_IP_UDP, 3, 
		{ EPM_PROTOCOL_NCADG, EPM_PROTOCOL_UDP, EPM_PROTOCOL_IP } },
	{ "ncalrpc", NCALRPC, 2, 
		{ EPM_PROTOCOL_NCALRPC, EPM_PROTOCOL_PIPE } },
	{ "ncacn_unix_stream", NCACN_UNIX_STREAM, 2, 
		{ EPM_PROTOCOL_NCACN, EPM_PROTOCOL_UNIX_DS } },
	{ "ncadg_unix_dgram", NCADG_UNIX_DGRAM, 2, 
		{ EPM_PROTOCOL_NCADG, EPM_PROTOCOL_UNIX_DS } },
	{ "ncacn_at_dsp", NCACN_AT_DSP, 3, 
		{ EPM_PROTOCOL_NCACN, EPM_PROTOCOL_APPLETALK, EPM_PROTOCOL_DSP } },
	{ "ncadg_at_ddp", NCADG_AT_DDP, 3, 
		{ EPM_PROTOCOL_NCADG, EPM_PROTOCOL_APPLETALK, EPM_PROTOCOL_DDP } },
	{ "ncacn_vns_ssp", NCACN_VNS_SPP, 3, 
		{ EPM_PROTOCOL_NCACN, EPM_PROTOCOL_STREETTALK, EPM_PROTOCOL_VINES_SPP } },
	{ "ncacn_vns_ipc", NCACN_VNS_IPC, 3, 
		{ EPM_PROTOCOL_NCACN, EPM_PROTOCOL_STREETTALK, EPM_PROTOCOL_VINES_IPC }, },
	{ "ncadg_ipx", NCADG_IPX, 2,
		{ EPM_PROTOCOL_NCADG, EPM_PROTOCOL_IPX },
	},
	{ "ncacn_spx", NCACN_SPX, 3,
		/* I guess some MS programmer confused the identifier for 
		 * EPM_PROTOCOL_UUID (0x0D or 13) with the one for 
		 * EPM_PROTOCOL_SPX (0x13) here. -- jelmer*/
		{ EPM_PROTOCOL_NCACN, EPM_PROTOCOL_NCALRPC, EPM_PROTOCOL_UUID },
	},
};

static const struct {
	const char *name;
	uint32_t flag;
} ncacn_options[] = {
	{"sign", DCERPC_SIGN},
	{"seal", DCERPC_SEAL},
	{"connect", DCERPC_CONNECT},
	{"spnego", DCERPC_AUTH_SPNEGO},
	{"krb5", DCERPC_AUTH_KRB5},
	{"validate", DCERPC_DEBUG_VALIDATE_BOTH},
	{"print", DCERPC_DEBUG_PRINT_BOTH},
	{"padcheck", DCERPC_DEBUG_PAD_CHECK},
	{"bigendian", DCERPC_PUSH_BIGENDIAN},
	{"smb2", DCERPC_SMB2}
};

const char *epm_floor_string(TALLOC_CTX *mem_ctx, struct epm_floor *epm_floor)
{
	struct GUID uuid;
	uint16_t if_version;
	NTSTATUS status;

	switch(epm_floor->lhs.protocol) {
		case EPM_PROTOCOL_UUID:
			status = dcerpc_floor_get_lhs_data(epm_floor, &uuid, &if_version);
			if (NT_STATUS_IS_OK(status)) {
				/* lhs is used: UUID */
				char *uuidstr;

				if (GUID_equal(&uuid, &ndr_transfer_syntax.uuid)) {
					return "NDR";
				} 

				if (GUID_equal(&uuid, &ndr64_transfer_syntax.uuid)) {
					return "NDR64";
				} 

				uuidstr = GUID_string(mem_ctx, &uuid);

				return talloc_asprintf(mem_ctx, " uuid %s/0x%02x", uuidstr, if_version);
			} else { /* IPX */
				return talloc_asprintf(mem_ctx, "IPX:%s", 
						data_blob_hex_string(mem_ctx, &epm_floor->rhs.uuid.unknown));
			}

		case EPM_PROTOCOL_NCACN:
			return "RPC-C";

		case EPM_PROTOCOL_NCADG:
			return "RPC";

		case EPM_PROTOCOL_NCALRPC:
			return "NCALRPC";

		case EPM_PROTOCOL_DNET_NSP:
			return "DNET/NSP";

		case EPM_PROTOCOL_IP:
			return talloc_asprintf(mem_ctx, "IP:%s", epm_floor->rhs.ip.ipaddr);

		case EPM_PROTOCOL_PIPE:
			return talloc_asprintf(mem_ctx, "PIPE:%s", epm_floor->rhs.pipe.path);

		case EPM_PROTOCOL_SMB:
			return talloc_asprintf(mem_ctx, "SMB:%s", epm_floor->rhs.smb.unc);

		case EPM_PROTOCOL_UNIX_DS:
			return talloc_asprintf(mem_ctx, "Unix:%s", epm_floor->rhs.unix_ds.path);

		case EPM_PROTOCOL_NETBIOS:
			return talloc_asprintf(mem_ctx, "NetBIOS:%s", epm_floor->rhs.netbios.name);

		case EPM_PROTOCOL_NETBEUI:
			return "NETBeui";

		case EPM_PROTOCOL_SPX:
			return "SPX";

		case EPM_PROTOCOL_NB_IPX:
			return "NB_IPX";

		case EPM_PROTOCOL_HTTP:
			return talloc_asprintf(mem_ctx, "HTTP:%d", epm_floor->rhs.http.port);

		case EPM_PROTOCOL_TCP:
			return talloc_asprintf(mem_ctx, "TCP:%d", epm_floor->rhs.tcp.port);

		case EPM_PROTOCOL_UDP:
			return talloc_asprintf(mem_ctx, "UDP:%d", epm_floor->rhs.udp.port);

		default:
			return talloc_asprintf(mem_ctx, "UNK(%02x):", epm_floor->lhs.protocol);
	}
}


/*
  form a binding string from a binding structure
*/
const char *dcerpc_binding_string(TALLOC_CTX *mem_ctx, const struct dcerpc_binding *b)
{
	char *s = talloc_strdup(mem_ctx, "");
	int i;
	const char *t_name=NULL;

	for (i=0;i<ARRAY_SIZE(transports);i++) {
		if (transports[i].transport == b->transport) {
			t_name = transports[i].name;
		}
	}
	if (!t_name) {
		return NULL;
	}

	if (!GUID_all_zero(&b->object)) { 
		s = talloc_asprintf(s, "%s@",
				    GUID_string(mem_ctx, &b->object));
	}

	s = talloc_asprintf_append(s, "%s:", t_name);
	if (!s) return NULL;

	if (b->host) {
		s = talloc_asprintf_append(s, "%s", b->host);
	}

	if (!b->endpoint && !b->options && !b->flags) {
		return s;
	}

	s = talloc_asprintf_append(s, "[");

	if (b->endpoint) {
		s = talloc_asprintf_append(s, "%s", b->endpoint);
	}

	/* this is a *really* inefficent way of dealing with strings,
	   but this is rarely called and the strings are always short,
	   so I don't care */
	for (i=0;b->options && b->options[i];i++) {
		s = talloc_asprintf_append(s, ",%s", b->options[i]);
		if (!s) return NULL;
	}

	for (i=0;i<ARRAY_SIZE(ncacn_options);i++) {
		if (b->flags & ncacn_options[i].flag) {
			s = talloc_asprintf_append(s, ",%s", ncacn_options[i].name);
			if (!s) return NULL;
		}
	}

	s = talloc_asprintf_append(s, "]");

	return s;
}

/*
  parse a binding string into a dcerpc_binding structure
*/
NTSTATUS dcerpc_parse_binding(TALLOC_CTX *mem_ctx, const char *s, struct dcerpc_binding **b_out)
{
	struct dcerpc_binding *b;
	char *options, *type;
	char *p;
	int i, j, comma_count;

	b = talloc(mem_ctx, struct dcerpc_binding);
	if (!b) {
		return NT_STATUS_NO_MEMORY;
	}

	p = strchr(s, '@');

	if (p && PTR_DIFF(p, s) == 36) { /* 36 is the length of a UUID */
		NTSTATUS status;

		status = GUID_from_string(s, &b->object);

		if (NT_STATUS_IS_ERR(status)) {
			DEBUG(0, ("Failed parsing UUID\n"));
			return status;
		}

		s = p + 1;
	} else {
		ZERO_STRUCT(b->object);
	}

	b->object_version = 0;

	p = strchr(s, ':');
	if (!p) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	type = talloc_strndup(mem_ctx, s, PTR_DIFF(p, s));
	if (!type) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<ARRAY_SIZE(transports);i++) {
		if (strcasecmp(type, transports[i].name) == 0) {
			b->transport = transports[i].transport;
			break;
		}
	}
	if (i==ARRAY_SIZE(transports)) {
		DEBUG(0,("Unknown dcerpc transport '%s'\n", type));
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	s = p+1;

	p = strchr(s, '[');
	if (p) {
		b->host = talloc_strndup(b, s, PTR_DIFF(p, s));
		options = talloc_strdup(mem_ctx, p+1);
		if (options[strlen(options)-1] != ']') {
			return NT_STATUS_INVALID_PARAMETER;
		}
		options[strlen(options)-1] = 0;
	} else {
		b->host = talloc_strdup(b, s);
		options = NULL;
	}

	if (!b->host) {
		return NT_STATUS_NO_MEMORY;
	}

	b->options = NULL;
	b->flags = 0;
	b->endpoint = NULL;

	if (!options) {
		*b_out = b;
		return NT_STATUS_OK;
	}

	comma_count = count_chars(options, ',');

	b->options = talloc_array(b, const char *, comma_count+2);
	if (!b->options) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; (p = strchr(options, ',')); i++) {
		b->options[i] = talloc_strndup(b, options, PTR_DIFF(p, options));
		if (!b->options[i]) {
			return NT_STATUS_NO_MEMORY;
		}
		options = p+1;
	}
	b->options[i] = options;
	b->options[i+1] = NULL;

	/* some options are pre-parsed for convenience */
	for (i=0;b->options[i];i++) {
		for (j=0;j<ARRAY_SIZE(ncacn_options);j++) {
			if (strcasecmp(ncacn_options[j].name, b->options[i]) == 0) {
				int k;
				b->flags |= ncacn_options[j].flag;
				for (k=i;b->options[k];k++) {
					b->options[k] = b->options[k+1];
				}
				i--;
				break;
			}
		}
	}

	if (b->options[0]) {
		/* Endpoint is first option */
		b->endpoint = b->options[0];
		if (strlen(b->endpoint) == 0) b->endpoint = NULL;

		for (i=0;b->options[i];i++) {
			b->options[i] = b->options[i+1];
		}
	}

	if (b->options[0] == NULL)
		b->options = NULL;
	
	*b_out = b;
	return NT_STATUS_OK;
}

NTSTATUS dcerpc_floor_get_lhs_data(struct epm_floor *epm_floor, struct GUID *uuid, uint16_t *if_version)
{
	TALLOC_CTX *mem_ctx = talloc_init("floor_get_lhs_data");
	struct ndr_pull *ndr = ndr_pull_init_blob(&epm_floor->lhs.lhs_data, mem_ctx);
	NTSTATUS status;
	
	ndr->flags |= LIBNDR_FLAG_NOALIGN;

	status = ndr_pull_GUID(ndr, NDR_SCALARS | NDR_BUFFERS, uuid);
	if (NT_STATUS_IS_ERR(status)) {
		talloc_free(mem_ctx);
		return status;
	}

	status = ndr_pull_uint16(ndr, NDR_SCALARS, if_version);

	talloc_free(mem_ctx);

	return status;
}

static DATA_BLOB dcerpc_floor_pack_lhs_data(TALLOC_CTX *mem_ctx, const struct GUID *uuid, uint32_t if_version)
{
	struct ndr_push *ndr = ndr_push_init_ctx(mem_ctx);

	ndr->flags |= LIBNDR_FLAG_NOALIGN;

	ndr_push_GUID(ndr, NDR_SCALARS | NDR_BUFFERS, uuid);
	ndr_push_uint16(ndr, NDR_SCALARS, if_version);

	return ndr_push_blob(ndr);
}

const char *dcerpc_floor_get_rhs_data(TALLOC_CTX *mem_ctx, struct epm_floor *epm_floor)
{
	switch (epm_floor->lhs.protocol) {
	case EPM_PROTOCOL_TCP:
		if (epm_floor->rhs.tcp.port == 0) return NULL;
		return talloc_asprintf(mem_ctx, "%d", epm_floor->rhs.tcp.port);
		
	case EPM_PROTOCOL_UDP:
		if (epm_floor->rhs.udp.port == 0) return NULL;
		return talloc_asprintf(mem_ctx, "%d", epm_floor->rhs.udp.port);

	case EPM_PROTOCOL_HTTP:
		if (epm_floor->rhs.http.port == 0) return NULL;
		return talloc_asprintf(mem_ctx, "%d", epm_floor->rhs.http.port);

	case EPM_PROTOCOL_IP:
		return talloc_strdup(mem_ctx, epm_floor->rhs.ip.ipaddr);

	case EPM_PROTOCOL_NCACN:
		return NULL;

	case EPM_PROTOCOL_NCADG:
		return NULL;

	case EPM_PROTOCOL_SMB:
		if (strlen(epm_floor->rhs.smb.unc) == 0) return NULL;
		return talloc_strdup(mem_ctx, epm_floor->rhs.smb.unc);

	case EPM_PROTOCOL_PIPE:
		if (strlen(epm_floor->rhs.pipe.path) == 0) return NULL;
		return talloc_strdup(mem_ctx, epm_floor->rhs.pipe.path);

	case EPM_PROTOCOL_NETBIOS:
		if (strlen(epm_floor->rhs.netbios.name) == 0) return NULL;
		return talloc_strdup(mem_ctx, epm_floor->rhs.netbios.name);

	case EPM_PROTOCOL_NCALRPC:
		return NULL;
		
	case EPM_PROTOCOL_VINES_SPP:
		return talloc_asprintf(mem_ctx, "%d", epm_floor->rhs.vines_spp.port);
		
	case EPM_PROTOCOL_VINES_IPC:
		return talloc_asprintf(mem_ctx, "%d", epm_floor->rhs.vines_ipc.port);
		
	case EPM_PROTOCOL_STREETTALK:
		return talloc_strdup(mem_ctx, epm_floor->rhs.streettalk.streettalk);
		
	case EPM_PROTOCOL_UNIX_DS:
		if (strlen(epm_floor->rhs.unix_ds.path) == 0) return NULL;
		return talloc_strdup(mem_ctx, epm_floor->rhs.unix_ds.path);
		
	case EPM_PROTOCOL_NULL:
		return NULL;

	default:
		DEBUG(0,("Unsupported lhs protocol %d\n", epm_floor->lhs.protocol));
		break;
	}

	return NULL;
}

static NTSTATUS dcerpc_floor_set_rhs_data(TALLOC_CTX *mem_ctx, struct epm_floor *epm_floor,  const char *data)
{
	switch (epm_floor->lhs.protocol) {
	case EPM_PROTOCOL_TCP:
		epm_floor->rhs.tcp.port = atoi(data);
		return NT_STATUS_OK;
		
	case EPM_PROTOCOL_UDP:
		epm_floor->rhs.udp.port = atoi(data);
		return NT_STATUS_OK;

	case EPM_PROTOCOL_HTTP:
		epm_floor->rhs.http.port = atoi(data);
		return NT_STATUS_OK;

	case EPM_PROTOCOL_IP:
		epm_floor->rhs.ip.ipaddr = talloc_strdup(mem_ctx, data);
		NT_STATUS_HAVE_NO_MEMORY(epm_floor->rhs.ip.ipaddr);
		return NT_STATUS_OK;

	case EPM_PROTOCOL_NCACN:
		epm_floor->rhs.ncacn.minor_version = 0;
		return NT_STATUS_OK;

	case EPM_PROTOCOL_NCADG:
		epm_floor->rhs.ncadg.minor_version = 0;
		return NT_STATUS_OK;

	case EPM_PROTOCOL_SMB:
		epm_floor->rhs.smb.unc = talloc_strdup(mem_ctx, data);
		NT_STATUS_HAVE_NO_MEMORY(epm_floor->rhs.smb.unc);
		return NT_STATUS_OK;

	case EPM_PROTOCOL_PIPE:
		epm_floor->rhs.pipe.path = talloc_strdup(mem_ctx, data);
		NT_STATUS_HAVE_NO_MEMORY(epm_floor->rhs.pipe.path);
		return NT_STATUS_OK;

	case EPM_PROTOCOL_NETBIOS:
		epm_floor->rhs.netbios.name = talloc_strdup(mem_ctx, data);
		NT_STATUS_HAVE_NO_MEMORY(epm_floor->rhs.netbios.name);
		return NT_STATUS_OK;

	case EPM_PROTOCOL_NCALRPC:
		return NT_STATUS_OK;
		
	case EPM_PROTOCOL_VINES_SPP:
		epm_floor->rhs.vines_spp.port = atoi(data);
		return NT_STATUS_OK;
		
	case EPM_PROTOCOL_VINES_IPC:
		epm_floor->rhs.vines_ipc.port = atoi(data);
		return NT_STATUS_OK;
		
	case EPM_PROTOCOL_STREETTALK:
		epm_floor->rhs.streettalk.streettalk = talloc_strdup(mem_ctx, data);
		NT_STATUS_HAVE_NO_MEMORY(epm_floor->rhs.streettalk.streettalk);
		return NT_STATUS_OK;
		
	case EPM_PROTOCOL_UNIX_DS:
		epm_floor->rhs.unix_ds.path = talloc_strdup(mem_ctx, data);
		NT_STATUS_HAVE_NO_MEMORY(epm_floor->rhs.unix_ds.path);
		return NT_STATUS_OK;
		
	case EPM_PROTOCOL_NULL:
		return NT_STATUS_OK;

	default:
		DEBUG(0,("Unsupported lhs protocol %d\n", epm_floor->lhs.protocol));
		break;
	}

	return NT_STATUS_NOT_SUPPORTED;
}

enum dcerpc_transport_t dcerpc_transport_by_endpoint_protocol(int prot)
{
	int i;

	/* Find a transport that has 'prot' as 4th protocol */
	for (i=0;i<ARRAY_SIZE(transports);i++) {
		if (transports[i].num_protocols >= 2 && 
			transports[i].protseq[1] == prot) {
			return transports[i].transport;
		}
	}
	
	/* Unknown transport */
	return -1;
}

enum dcerpc_transport_t dcerpc_transport_by_tower(struct epm_tower *tower)
{
	int i;

	/* Find a transport that matches this tower */
	for (i=0;i<ARRAY_SIZE(transports);i++) {
		int j;
		if (transports[i].num_protocols != tower->num_floors - 2) {
			continue; 
		}

		for (j = 0; j < transports[i].num_protocols; j++) {
			if (transports[i].protseq[j] != tower->floors[j+2].lhs.protocol) {
				break;
			}
		}

		if (j == transports[i].num_protocols) {
			return transports[i].transport;
		}
	}
	
	/* Unknown transport */
	return -1;
}

NTSTATUS dcerpc_binding_from_tower(TALLOC_CTX *mem_ctx, struct epm_tower *tower, struct dcerpc_binding **b_out)
{
	NTSTATUS status;
	struct dcerpc_binding *binding;

	binding = talloc(mem_ctx, struct dcerpc_binding);
	NT_STATUS_HAVE_NO_MEMORY(binding);

	ZERO_STRUCT(binding->object);
	binding->options = NULL;
	binding->host = NULL;
	binding->flags = 0;

	binding->transport = dcerpc_transport_by_tower(tower);

	if (binding->transport == -1) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (tower->num_floors < 1) {
		return NT_STATUS_OK;
	}

	/* Set object uuid */
	status = dcerpc_floor_get_lhs_data(&tower->floors[0], &binding->object, &binding->object_version);
	
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Error pulling object uuid and version: %s", nt_errstr(status)));	
		return status;
	}

	/* Ignore floor 1, it contains the NDR version info */
	
	binding->options = NULL;

	/* Set endpoint */
	if (tower->num_floors >= 4) {
		binding->endpoint = dcerpc_floor_get_rhs_data(mem_ctx, &tower->floors[3]);
	} else {
		binding->endpoint = NULL;
	}

	/* Set network address */
	if (tower->num_floors >= 5) {
		binding->host = dcerpc_floor_get_rhs_data(mem_ctx, &tower->floors[4]);
	}
	*b_out = binding;
	return NT_STATUS_OK;
}

NTSTATUS dcerpc_binding_build_tower(TALLOC_CTX *mem_ctx, struct dcerpc_binding *binding, struct epm_tower *tower)
{
	const enum epm_protocol *protseq = NULL;
	int num_protocols = -1, i;
	NTSTATUS status;
	
	/* Find transport */
	for (i=0;i<ARRAY_SIZE(transports);i++) {
		if (transports[i].transport == binding->transport) {
			protseq = transports[i].protseq;
			num_protocols = transports[i].num_protocols;
			break;
		}
	}

	if (num_protocols == -1) {
		DEBUG(0, ("Unable to find transport with id '%d'\n", binding->transport));
		return NT_STATUS_UNSUCCESSFUL;
	}

	tower->num_floors = 2 + num_protocols;
	tower->floors = talloc_array(mem_ctx, struct epm_floor, tower->num_floors);

	/* Floor 0 */
	tower->floors[0].lhs.protocol = EPM_PROTOCOL_UUID;

	tower->floors[0].lhs.lhs_data = dcerpc_floor_pack_lhs_data(mem_ctx, &binding->object, binding->object_version);

	tower->floors[0].rhs.uuid.unknown = data_blob_talloc_zero(mem_ctx, 2);
	
	/* Floor 1 */
	tower->floors[1].lhs.protocol = EPM_PROTOCOL_UUID;

	tower->floors[1].lhs.lhs_data = dcerpc_floor_pack_lhs_data(mem_ctx, 
								&ndr_transfer_syntax.uuid, 
								ndr_transfer_syntax.if_version);
	
	tower->floors[1].rhs.uuid.unknown = data_blob_talloc_zero(mem_ctx, 2);
	
	/* Floor 2 to num_protocols */
	for (i = 0; i < num_protocols; i++) {
		tower->floors[2 + i].lhs.protocol = protseq[i];
		tower->floors[2 + i].lhs.lhs_data = data_blob_talloc(mem_ctx, NULL, 0);
		ZERO_STRUCT(tower->floors[2 + i].rhs);
		dcerpc_floor_set_rhs_data(mem_ctx, &tower->floors[2 + i], "");
	}

	/* The 4th floor contains the endpoint */
	if (num_protocols >= 2 && binding->endpoint) {
		status = dcerpc_floor_set_rhs_data(mem_ctx, &tower->floors[3], binding->endpoint);
		if (NT_STATUS_IS_ERR(status)) {
			return status;
		}
	}
	
	/* The 5th contains the network address */
	if (num_protocols >= 3 && binding->host) {
		if (is_ipaddress(binding->host)) {
			status = dcerpc_floor_set_rhs_data(mem_ctx, &tower->floors[4], 
							   binding->host);
		} else {
			/* note that we don't attempt to resolve the
			   name here - when we get a hostname here we
			   are in the client code, and want to put in
			   a wildcard all-zeros IP for the server to
			   fill in */
			status = dcerpc_floor_set_rhs_data(mem_ctx, &tower->floors[4], 
							   "0.0.0.0");
		}
		if (NT_STATUS_IS_ERR(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}


struct epm_map_binding_state {
	struct dcerpc_binding *binding;
	const struct dcerpc_interface_table *table;
	struct dcerpc_pipe *pipe;
	struct epm_twr_t twr;
	struct epm_twr_t *twr_r;
	struct epm_Map r;
};


static void continue_epm_recv_binding(struct composite_context *ctx);
static void continue_epm_map(struct rpc_request *req);


static void continue_epm_recv_binding(struct composite_context *ctx)
{
	struct policy_handle handle;
	struct GUID guid;
	struct rpc_request *map_req;

	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct epm_map_binding_state *s = talloc_get_type(c->private_data,
							  struct epm_map_binding_state);

	c->status = dcerpc_pipe_connect_b_recv(ctx, c, &s->pipe);
	if (!composite_is_ok(c)) return;

	ZERO_STRUCT(handle);
	ZERO_STRUCT(guid);

	s->binding->object         = s->table->uuid;
	s->binding->object_version = s->table->if_version;

	c->status = dcerpc_binding_build_tower(s->pipe, s->binding, &s->twr.tower);
	if (!composite_is_ok(c)) return;
	
	/* with some nice pretty paper around it of course */
	s->r.in.object        = &guid;
	s->r.in.map_tower     = &s->twr;
	s->r.in.entry_handle  = &handle;
	s->r.in.max_towers    = 1;
	s->r.out.entry_handle = &handle;

	map_req = dcerpc_epm_Map_send(s->pipe, c, &s->r);
	if (composite_nomem(map_req, c)) return;
	
	composite_continue_rpc(c, map_req, continue_epm_map, c);
}


static void continue_epm_map(struct rpc_request *req)
{
	struct composite_context *c = talloc_get_type(req->async.private,
						      struct composite_context);
	struct epm_map_binding_state *s = talloc_get_type(c->private_data,
							  struct epm_map_binding_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	if (s->r.out.result != 0 || s->r.out.num_towers != 1) {
		composite_error(c, NT_STATUS_PORT_UNREACHABLE);
		return;
	}
	
	s->twr_r = s->r.out.towers[0].twr;
	if (s->twr_r == NULL) {
		composite_error(c, NT_STATUS_PORT_UNREACHABLE);
		return;
	}

	if (s->twr_r->tower.num_floors != s->twr.tower.num_floors ||
	    s->twr_r->tower.floors[3].lhs.protocol != s->twr.tower.floors[3].lhs.protocol) {
		composite_error(c, NT_STATUS_PORT_UNREACHABLE);
		return;
	}

	s->binding->endpoint = talloc_reference(s->binding,
						dcerpc_floor_get_rhs_data(c, &s->twr_r->tower.floors[3]));
	composite_done(c);
}


struct composite_context *dcerpc_epm_map_binding_send(TALLOC_CTX *mem_ctx,
						      struct dcerpc_binding *binding,
						      const struct dcerpc_interface_table *table,
						      struct event_context *ev)
{
	struct composite_context *c;
	struct epm_map_binding_state *s;
	struct composite_context *pipe_connect_req;

	NTSTATUS status;
	struct dcerpc_binding *epmapper_binding;
	int i;

	/* composite context allocation and setup */
	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct epm_map_binding_state);
	if (composite_nomem(s, c)) return c;

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = s;
	c->event_ctx = ev;
	
	s->binding = binding;
	s->table   = table;

	struct cli_credentials *anon_creds = cli_credentials_init(mem_ctx);
	cli_credentials_set_conf(anon_creds);
	cli_credentials_set_anonymous(anon_creds);

	/* First, check if there is a default endpoint specified in the IDL */

	if (table) {
		struct dcerpc_binding *default_binding;

		/* Find one of the default pipes for this interface */
		for (i = 0; i < table->endpoints->count; i++) {
			status = dcerpc_parse_binding(mem_ctx, table->endpoints->names[i], &default_binding);

			if (NT_STATUS_IS_OK(status)) {
				if (default_binding->transport == binding->transport && default_binding->endpoint) {
					binding->endpoint = talloc_reference(binding, default_binding->endpoint);
					talloc_free(default_binding);

					composite_done(c);
					return c;

				} else {
					talloc_free(default_binding);
				}
			}
		}
	}

	epmapper_binding = talloc_zero(c, struct dcerpc_binding);
	if (composite_nomem(epmapper_binding, c)) return c;

	epmapper_binding->transport  = binding->transport;
	epmapper_binding->host       = talloc_reference(epmapper_binding, binding->host);
	epmapper_binding->options    = NULL;
	epmapper_binding->flags      = 0;
	epmapper_binding->endpoint   = NULL;

	pipe_connect_req = dcerpc_pipe_connect_b_send(c, &s->pipe, epmapper_binding, &dcerpc_table_epmapper,
						      anon_creds, ev);
	if (composite_nomem(pipe_connect_req, c)) return c;
	
	composite_continue(c, pipe_connect_req, continue_epm_recv_binding, c);
	return c;
}


NTSTATUS dcerpc_epm_map_binding_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);
	
	talloc_free(c);
	return status;
}



NTSTATUS dcerpc_epm_map_binding(TALLOC_CTX *mem_ctx, struct dcerpc_binding *binding,
				const struct dcerpc_interface_table *table, struct event_context *ev)
{
	struct dcerpc_pipe *p;
	NTSTATUS status;
	struct policy_handle handle;
	struct GUID guid;
	struct epm_Map r;
	struct epm_twr_t twr, *twr_r;
	struct dcerpc_binding *epmapper_binding;
	int i;

	struct cli_credentials *anon_creds
		= cli_credentials_init(mem_ctx);
	cli_credentials_set_conf(anon_creds);
	cli_credentials_set_anonymous(anon_creds);

	/* First, check if there is a default endpoint specified in the IDL */

	if (table) {
		struct dcerpc_binding *default_binding;

		/* Find one of the default pipes for this interface */
		for (i = 0; i < table->endpoints->count; i++) {
			status = dcerpc_parse_binding(mem_ctx, table->endpoints->names[i], &default_binding);

			if (NT_STATUS_IS_OK(status)) {
				if (default_binding->transport == binding->transport && default_binding->endpoint) {
					binding->endpoint = talloc_reference(binding, default_binding->endpoint);
					talloc_free(default_binding);
					return NT_STATUS_OK;
				} else {
					talloc_free(default_binding);
				}
			}
		}
	}

	epmapper_binding = talloc_zero(mem_ctx, struct dcerpc_binding);
	if (!epmapper_binding) {
		return NT_STATUS_NO_MEMORY;
	}

	epmapper_binding->transport = binding->transport;
	epmapper_binding->host = talloc_reference(epmapper_binding, 
						  binding->host);
	epmapper_binding->options = NULL;
	epmapper_binding->flags = 0;
	epmapper_binding->endpoint = NULL;
	
	status = dcerpc_pipe_connect_b(mem_ctx, 
				       &p,
				       epmapper_binding,
				       &dcerpc_table_epmapper,
				       anon_creds, ev);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ZERO_STRUCT(handle);
	ZERO_STRUCT(guid);

	binding->object = table->uuid;
	binding->object_version = table->if_version;

	status = dcerpc_binding_build_tower(p, binding, &twr.tower);
	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	/* with some nice pretty paper around it of course */
	r.in.object = &guid;
	r.in.map_tower = &twr;
	r.in.entry_handle = &handle;
	r.in.max_towers = 1;
	r.out.entry_handle = &handle;

	status = dcerpc_epm_Map(p, p, &r);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(p);
		return status;
	}
	if (r.out.result != 0 || r.out.num_towers != 1) {
		talloc_free(p);
		return NT_STATUS_PORT_UNREACHABLE;
	}

	twr_r = r.out.towers[0].twr;
	if (!twr_r) {
		talloc_free(p);
		return NT_STATUS_PORT_UNREACHABLE;
	}

	if (twr_r->tower.num_floors != twr.tower.num_floors ||
	    twr_r->tower.floors[3].lhs.protocol != twr.tower.floors[3].lhs.protocol) {
		talloc_free(p);
		return NT_STATUS_PORT_UNREACHABLE;
	}

	binding->endpoint = talloc_reference(binding, dcerpc_floor_get_rhs_data(mem_ctx, &twr_r->tower.floors[3]));

	talloc_free(p);

	return NT_STATUS_OK;
}


struct pipe_auth_state {
	struct dcerpc_pipe *pipe;
	struct dcerpc_binding *binding;
	const struct dcerpc_interface_table *table;
	struct cli_credentials *credentials;
};


static void continue_auth_schannel(struct composite_context *ctx);
static void continue_auth(struct composite_context *ctx);
static void continue_auth_none(struct composite_context *ctx);


static void continue_auth_schannel(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);

	c->status = dcerpc_bind_auth_schannel_recv(ctx);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


static void continue_auth(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);

	c->status = dcerpc_bind_auth_recv(ctx);
	if (!composite_is_ok(c)) return;
	
	composite_done(c);
}


static void continue_auth_none(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);

	c->status = dcerpc_bind_auth_none_recv(ctx);
	if (!composite_is_ok(c)) return;
	
	composite_done(c);
}


struct composite_context *dcerpc_pipe_auth_send(struct dcerpc_pipe *p, 
						struct dcerpc_binding *binding,
						const struct dcerpc_interface_table *table,
						struct cli_credentials *credentials)
{
	struct composite_context *c;
	struct pipe_auth_state *s;
	struct composite_context *auth_schannel_req;
	struct composite_context *auth_req;
	struct composite_context *auth_none_req;

	/* composite context allocation and setup */
	c = talloc_zero(NULL, struct composite_context);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_auth_state);
	if (composite_nomem(s, c)) return c;

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = s;
	c->event_ctx = p->conn->event_ctx;

	s->binding      = binding;
	s->table        = table;
	s->credentials  = credentials;
	s->pipe         = p;

	s->pipe->conn->flags = binding->flags;
	
	/* remember the binding string for possible secondary connections */
	s->pipe->conn->binding_string = dcerpc_binding_string(p, binding);

	if (!cli_credentials_is_anonymous(s->credentials) &&
	    (binding->flags & DCERPC_SCHANNEL) &&
	    !cli_credentials_get_netlogon_creds(s->credentials)) {

		/* If we don't already have netlogon credentials for
		 * the schannel bind, then we have to get these
		 * first */
		auth_schannel_req = dcerpc_bind_auth_schannel_send(c, s->pipe, s->table,
								   s->credentials,
								   dcerpc_auth_level(s->pipe->conn));
		if (composite_nomem(auth_schannel_req, c)) return c;

		composite_continue(c, auth_schannel_req, continue_auth_schannel, c);

	} else if (!cli_credentials_is_anonymous(s->credentials) &&
		   !(s->pipe->conn->transport.transport == NCACN_NP &&
		     !(s->binding->flags & DCERPC_SIGN) &&
		     !(s->binding->flags & DCERPC_SEAL))) {

		/* Perform an authenticated DCE-RPC bind, except where
		 * we ask for a connection on NCACN_NP, and that
		 * connection is not signed or sealed.  For that case
		 * we rely on the already authenticated CIFS connection
		 */
		
		uint8_t auth_type;

		if ((s->pipe->conn->flags & (DCERPC_SIGN|DCERPC_SEAL)) == 0) {
			/*
			  we are doing an authenticated connection,
			  but not using sign or seal. We must force
			  the CONNECT dcerpc auth type as a NONE auth
			  type doesn't allow authentication
			  information to be passed.
			*/
			s->pipe->conn->flags |= DCERPC_CONNECT;
		}

		if (s->binding->flags & DCERPC_AUTH_SPNEGO) {
			auth_type = DCERPC_AUTH_TYPE_SPNEGO;

		} else if (s->binding->flags & DCERPC_AUTH_KRB5) {
			auth_type = DCERPC_AUTH_TYPE_KRB5;

		} else if (s->binding->flags & DCERPC_SCHANNEL) {
			auth_type = DCERPC_AUTH_TYPE_SCHANNEL;

		} else {
			auth_type = DCERPC_AUTH_TYPE_NTLMSSP;
		}
		
		auth_req = dcerpc_bind_auth_send(c, s->pipe, s->table,
						 s->credentials, auth_type,
						 dcerpc_auth_level(s->pipe->conn),
						 s->table->authservices->names[0]);
		if (composite_nomem(auth_req, c)) return c;
		
		composite_continue(c, auth_req, continue_auth, c);

	} else {
		auth_none_req = dcerpc_bind_auth_none_send(c, s->pipe, s->table);
		if (composite_nomem(auth_none_req, c)) return c;

		composite_continue(c, auth_none_req, continue_auth_none, c);
	}

	return c;
}


NTSTATUS dcerpc_pipe_auth_recv(struct composite_context *c)
{
	NTSTATUS status;

	struct pipe_auth_state *s = talloc_get_type(c->private_data,
						    struct pipe_auth_state);
	status = composite_wait(c);
	if (!NT_STATUS_IS_OK(status)) {
		char *uuid_str = GUID_string(s->pipe, &s->table->uuid);
		DEBUG(0, ("Failed to bind to uuid %s - %s\n", uuid_str, nt_errstr(status)));
		talloc_free(uuid_str);
	}

	talloc_free(c);
	return status;
}


/* 
   perform an authenticated bind if needed
*/
NTSTATUS dcerpc_pipe_auth(struct dcerpc_pipe *p, 
			  struct dcerpc_binding *binding,
			  const struct dcerpc_interface_table *table,
			  struct cli_credentials *credentials)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;
	tmp_ctx = talloc_new(p);

	p->conn->flags = binding->flags;

	/* remember the binding string for possible secondary connections */
	p->conn->binding_string = dcerpc_binding_string(p, binding);

	if (!cli_credentials_is_anonymous(credentials) &&
		(binding->flags & DCERPC_SCHANNEL) && 
		!cli_credentials_get_netlogon_creds(credentials)) {
		
		/* If we don't already have netlogon credentials for
		 * the schannel bind, then we have to get these
		 * first */
		status = dcerpc_bind_auth_schannel(tmp_ctx, p, table, credentials,
						   dcerpc_auth_level(p->conn));
	} else if (!cli_credentials_is_anonymous(credentials) &&
		!(p->conn->transport.transport == NCACN_NP &&
		  !(binding->flags & DCERPC_SIGN) &&
		  !(binding->flags & DCERPC_SEAL))) { 	
	
		/* Perform an authenticated DCE-RPC bind, except where
		 * we ask for a connection on NCACN_NP, and that
		 * connection is not signed or sealed.  For that case
		 * we rely on the already authenicated CIFS connection
		 */

		uint8_t auth_type;
		
		if ((p->conn->flags & (DCERPC_SIGN|DCERPC_SEAL)) == 0) {
			/*
			  we are doing an authenticated connection,
			  but not using sign or seal. We must force
			  the CONNECT dcerpc auth type as a NONE auth
			  type doesn't allow authentication
			  information to be passed.
			*/
			p->conn->flags |= DCERPC_CONNECT;
		}

		if (binding->flags & DCERPC_AUTH_SPNEGO) {
			auth_type = DCERPC_AUTH_TYPE_SPNEGO;
		} else if (binding->flags & DCERPC_AUTH_KRB5) {
			auth_type = DCERPC_AUTH_TYPE_KRB5;
		} else if (binding->flags & DCERPC_SCHANNEL) {
			auth_type = DCERPC_AUTH_TYPE_SCHANNEL;
		} else {
			auth_type = DCERPC_AUTH_TYPE_NTLMSSP;
		}

		status = dcerpc_bind_auth(p, table,
					  credentials, auth_type, 
					  dcerpc_auth_level(p->conn),
					  table->authservices->names[0]);
	} else {
		status = dcerpc_bind_auth_none(p, table);
	}

	if (!NT_STATUS_IS_OK(status)) {
		char *uuid_str = GUID_string(p, &table->uuid);
		DEBUG(0,("Failed to bind to uuid %s - %s\n", uuid_str, nt_errstr(status)));
		talloc_free(uuid_str);
	}
	talloc_free(tmp_ctx);
	return status;
}


NTSTATUS dcerpc_generic_session_key(struct dcerpc_connection *c,
				    DATA_BLOB *session_key)
{
	/* this took quite a few CPU cycles to find ... */
	session_key->data = discard_const_p(unsigned char, "SystemLibraryDTC");
	session_key->length = 16;
	return NT_STATUS_OK;
}

/*
  fetch the user session key - may be default (above) or the SMB session key
*/
NTSTATUS dcerpc_fetch_session_key(struct dcerpc_pipe *p,
				  DATA_BLOB *session_key)
{
	return p->conn->security_state.session_key(p->conn, session_key);
}


/*
  log a rpc packet in a format suitable for ndrdump. This is especially useful
  for sealed packets, where ethereal cannot easily see the contents

  this triggers on a debug level of >= 10
*/
void dcerpc_log_packet(const struct dcerpc_interface_table *ndr,
		       uint32_t opnum, uint32_t flags, DATA_BLOB *pkt)
{
	const int num_examples = 20;
	int i;

	if (DEBUGLEVEL < 10) return;

	for (i=0;i<num_examples;i++) {
		char *name=NULL;
		asprintf(&name, "%s/rpclog/%s-%u.%d.%s", 
			 lp_lockdir(), ndr->name, opnum, i,
			 (flags&NDR_IN)?"in":"out");
		if (name == NULL) {
			return;
		}
		if (!file_exist(name)) {
			if (file_save(name, pkt->data, pkt->length)) {
				DEBUG(10,("Logged rpc packet to %s\n", name));
			}
			free(name);
			break;
		}
		free(name);
	}
}



/*
  create a secondary context from a primary connection

  this uses dcerpc_alter_context() to create a new dcerpc context_id
*/
NTSTATUS dcerpc_secondary_context(struct dcerpc_pipe *p, 
				  struct dcerpc_pipe **pp2,
				  const struct dcerpc_interface_table *table)
{
	NTSTATUS status;
	struct dcerpc_pipe *p2;
	
	p2 = talloc_zero(p, struct dcerpc_pipe);
	if (p2 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	p2->conn = talloc_reference(p2, p->conn);
	p2->request_timeout = p->request_timeout;

	p2->context_id = ++p->conn->next_context_id;

	p2->syntax.uuid = table->uuid;
	p2->syntax.if_version = table->if_version;

	p2->transfer_syntax = ndr_transfer_syntax;

	status = dcerpc_alter_context(p2, p2, &p2->syntax, &p2->transfer_syntax);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(p2);
		return status;
	}

	*pp2 = p2;

	return status;
}
