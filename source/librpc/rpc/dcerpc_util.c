/* 
   Unix SMB/CIFS implementation.

   dcerpc utility functions

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Jelmer Vernooij 2004
   
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


/*
  find the pipe name for a local IDL interface
*/
const char *idl_pipe_name(const char *uuid, uint32_t if_version)
{
	int i;
	for (i=0;dcerpc_pipes[i];i++) {
		if (strcasecmp(dcerpc_pipes[i]->uuid, uuid) == 0 &&
		    dcerpc_pipes[i]->if_version == if_version) {
			return dcerpc_pipes[i]->name;
		}
	}
	return "UNKNOWN";
}

/*
  find the number of calls defined by local IDL
*/
int idl_num_calls(const char *uuid, uint32_t if_version)
{
	int i;
	for (i=0;dcerpc_pipes[i];i++) {
		if (strcasecmp(dcerpc_pipes[i]->uuid, uuid) == 0 &&
		    dcerpc_pipes[i]->if_version == if_version) {
			return dcerpc_pipes[i]->num_calls;
		}
	}
	return -1;
}


/*
  find a dcerpc interface by name
*/
const struct dcerpc_interface_table *idl_iface_by_name(const char *name)
{
	int i;
	for (i=0;dcerpc_pipes[i];i++) {
		if (strcasecmp(dcerpc_pipes[i]->name, name) == 0) {
			return dcerpc_pipes[i];
		}
	}
	return NULL;
}

/*
  find a dcerpc interface by uuid
*/
const struct dcerpc_interface_table *idl_iface_by_uuid(const char *uuid)
{
	int i;
	for (i=0;dcerpc_pipes[i];i++) {
		if (strcasecmp(dcerpc_pipes[i]->uuid, uuid) == 0) {
			return dcerpc_pipes[i];
		}
	}
	return NULL;
}



/* 
   push a dcerpc_packet into a blob, potentially with auth info
*/
NTSTATUS dcerpc_push_auth(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, 
			  struct dcerpc_packet *pkt,
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

	if (auth_info) {
		pkt->auth_length = auth_info->credentials.length;
	} else {
		pkt->auth_length = 0;
	}

	status = ndr_push_dcerpc_packet(ndr, NDR_SCALARS|NDR_BUFFERS, pkt);
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
	enum epm_protocols protseq[MAX_PROTSEQ];
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
};

static const struct {
	const char *name;
	uint32_t flag;
} ncacn_options[] = {
	{"sign", DCERPC_SIGN},
	{"seal", DCERPC_SEAL},
	{"connect", DCERPC_CONNECT},
	{"validate", DCERPC_DEBUG_VALIDATE_BOTH},
	{"print", DCERPC_DEBUG_PRINT_BOTH},
	{"padcheck", DCERPC_DEBUG_PAD_CHECK},
	{"bigendian", DCERPC_PUSH_BIGENDIAN}
};



/*
  form a binding string from a binding structure
*/
const char *dcerpc_binding_string(TALLOC_CTX *mem_ctx, const struct dcerpc_binding *b)
{
	char *s = NULL;
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

	if (!uuid_all_zero(&b->object)) { 
		s = talloc_asprintf(mem_ctx, "%s@", GUID_string(mem_ctx, &b->object));
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
NTSTATUS dcerpc_parse_binding(TALLOC_CTX *mem_ctx, const char *s, struct dcerpc_binding *b)
{
	char *options, *type;
	char *p;
	int i, j, comma_count;

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
		b->host = talloc_strndup(mem_ctx, s, PTR_DIFF(p, s));
		options = talloc_strdup(mem_ctx, p+1);
		if (options[strlen(options)-1] != ']') {
			return NT_STATUS_INVALID_PARAMETER;
		}
		options[strlen(options)-1] = 0;
	} else {
		b->host = talloc_strdup(mem_ctx, s);
		options = NULL;
	}

	if (!b->host) {
		return NT_STATUS_NO_MEMORY;
	}

	b->options = NULL;
	b->flags = 0;
	b->endpoint = NULL;

	if (!options) {
		return NT_STATUS_OK;
	}

	comma_count = count_chars(options, ',');

	b->options = talloc_array_p(mem_ctx, const char *, comma_count+2);
	if (!b->options) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; (p = strchr(options, ',')); i++) {
		b->options[i] = talloc_strndup(mem_ctx, options, PTR_DIFF(p, options));
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
	
	return NT_STATUS_OK;
}

const char *dcerpc_floor_get_rhs_data(TALLOC_CTX *mem_ctx, struct epm_floor *floor)
{
	switch (floor->lhs.protocol) {
	case EPM_PROTOCOL_TCP:
		if (floor->rhs.tcp.port == 0) return NULL;
		return talloc_asprintf(mem_ctx, "%d", floor->rhs.tcp.port);
		
	case EPM_PROTOCOL_UDP:
		if (floor->rhs.udp.port == 0) return NULL;
		return talloc_asprintf(mem_ctx, "%d", floor->rhs.udp.port);

	case EPM_PROTOCOL_HTTP:
		if (floor->rhs.http.port == 0) return NULL;
		return talloc_asprintf(mem_ctx, "%d", floor->rhs.http.port);

	case EPM_PROTOCOL_IP:
		if (floor->rhs.ip.address == 0) {
			return NULL; 
		}

		{
         	struct in_addr in;
			in.s_addr = htonl(floor->rhs.ip.address);
            return talloc_strdup(mem_ctx, inet_ntoa(in));
		}

	case EPM_PROTOCOL_NCACN:
		return NULL;

	case EPM_PROTOCOL_NCADG:
		return NULL;

	case EPM_PROTOCOL_SMB:
		if (strlen(floor->rhs.smb.unc) == 0) return NULL;
		return talloc_strdup(mem_ctx, floor->rhs.smb.unc);

	case EPM_PROTOCOL_PIPE:
		if (strlen(floor->rhs.pipe.path) == 0) return NULL;
		return talloc_strdup(mem_ctx, floor->rhs.pipe.path);

	case EPM_PROTOCOL_NETBIOS:
		if (strlen(floor->rhs.netbios.name) == 0) return NULL;
		return talloc_strdup(mem_ctx, floor->rhs.netbios.name);

	case EPM_PROTOCOL_NCALRPC:
		return NULL;
		
	case EPM_PROTOCOL_VINES_SPP:
		return talloc_asprintf(mem_ctx, "%d", floor->rhs.vines_spp.port);
		
	case EPM_PROTOCOL_VINES_IPC:
		return talloc_asprintf(mem_ctx, "%d", floor->rhs.vines_ipc.port);
		
	case EPM_PROTOCOL_STREETTALK:
		return talloc_strdup(mem_ctx, floor->rhs.streettalk.streettalk);
		
	case EPM_PROTOCOL_UNIX_DS:
		if (strlen(floor->rhs.unix_ds.path) == 0) return NULL;
		return talloc_strdup(mem_ctx, floor->rhs.unix_ds.path);
		
	case EPM_PROTOCOL_NULL:
		return NULL;
	}

	return NULL;
}

static NTSTATUS dcerpc_floor_set_rhs_data(TALLOC_CTX *mem_ctx, struct epm_floor *floor,  const char *data)
{
	switch (floor->lhs.protocol) {
	case EPM_PROTOCOL_TCP:
		floor->rhs.tcp.port = atoi(data);
		return NT_STATUS_OK;
		
	case EPM_PROTOCOL_UDP:
		floor->rhs.udp.port = atoi(data);
		return NT_STATUS_OK;

	case EPM_PROTOCOL_HTTP:
		floor->rhs.http.port = atoi(data);
		return NT_STATUS_OK;

	case EPM_PROTOCOL_IP:
		if (strlen(data) > 0) {
			floor->rhs.ip.address = interpret_addr(data);
		} else {
			floor->rhs.ip.address = 0;
		}
		return NT_STATUS_OK;

	case EPM_PROTOCOL_NCACN:
		floor->rhs.ncacn.minor_version = 0;
		return NT_STATUS_OK;

	case EPM_PROTOCOL_NCADG:
		floor->rhs.ncadg.minor_version = 0;
		return NT_STATUS_OK;

	case EPM_PROTOCOL_SMB:
		floor->rhs.smb.unc = talloc_strdup(mem_ctx, data);
		if (!floor->rhs.smb.unc) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;

	case EPM_PROTOCOL_PIPE:
		floor->rhs.pipe.path = talloc_strdup(mem_ctx, data);
		if (!floor->rhs.pipe.path) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;

	case EPM_PROTOCOL_NETBIOS:
		floor->rhs.netbios.name = talloc_strdup(mem_ctx, data);
		if (!floor->rhs.netbios.name) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;

	case EPM_PROTOCOL_NCALRPC:
		return NT_STATUS_OK;
		
	case EPM_PROTOCOL_VINES_SPP:
		floor->rhs.vines_spp.port = atoi(data);
		return NT_STATUS_OK;
		
	case EPM_PROTOCOL_VINES_IPC:
		floor->rhs.vines_ipc.port = atoi(data);
		return NT_STATUS_OK;
		
	case EPM_PROTOCOL_STREETTALK:
		floor->rhs.streettalk.streettalk = talloc_strdup(mem_ctx, data);
		if (!floor->rhs.streettalk.streettalk) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
		
	case EPM_PROTOCOL_UNIX_DS:
		floor->rhs.unix_ds.path = talloc_strdup(mem_ctx, data);
		if (!floor->rhs.unix_ds.path) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
		
	case EPM_PROTOCOL_NULL:
		return NT_STATUS_OK;
	}

	return NT_STATUS_NOT_SUPPORTED;
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

NTSTATUS dcerpc_binding_from_tower(TALLOC_CTX *mem_ctx, struct epm_tower *tower, struct dcerpc_binding *binding)
{
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
	binding->object = tower->floors[0].lhs.info.uuid.uuid;
	binding->object_version = tower->floors[0].lhs.info.uuid.version;

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
	return NT_STATUS_OK;
}

NTSTATUS dcerpc_binding_build_tower(TALLOC_CTX *mem_ctx, struct dcerpc_binding *binding, struct epm_tower *tower)
{
	const enum epm_protocols *protseq;
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
	tower->floors = talloc_array_p(mem_ctx, struct epm_floor, tower->num_floors);

	/* Floor 0 */
	tower->floors[0].lhs.protocol = EPM_PROTOCOL_UUID;
	tower->floors[0].lhs.info.uuid.uuid = binding->object;
	tower->floors[0].lhs.info.uuid.version = binding->object_version;
	tower->floors[0].rhs.uuid.unknown = 0;
	
	/* Floor 1 */
	tower->floors[1].lhs.protocol = EPM_PROTOCOL_UUID;
	tower->floors[1].lhs.info.uuid.version = NDR_GUID_VERSION;
	tower->floors[1].rhs.uuid.unknown = 0;
	status = GUID_from_string(NDR_GUID, &tower->floors[1].lhs.info.uuid.uuid);
	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	/* Floor 2 to num_protocols */
	for (i = 0; i < num_protocols; i++) {
		tower->floors[2 + i].lhs.protocol = protseq[i];
		tower->floors[2 + i].lhs.info.lhs_data = data_blob_talloc(mem_ctx, NULL, 0);
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
		status = dcerpc_floor_set_rhs_data(mem_ctx, &tower->floors[4], binding->host);
		if (NT_STATUS_IS_ERR(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}

NTSTATUS dcerpc_epm_map_binding(TALLOC_CTX *mem_ctx, struct dcerpc_binding *binding,
				 const char *uuid, uint_t version)
{
	struct dcerpc_pipe *p;
	NTSTATUS status;
	struct epm_Map r;
	struct policy_handle handle;
	struct GUID guid;
	struct epm_twr_t twr, *twr_r;
	struct dcerpc_binding epmapper_binding;


	if (!strcmp(uuid, DCERPC_EPMAPPER_UUID)) {
		switch(binding->transport) {
			case NCACN_IP_TCP: binding->endpoint = talloc_asprintf(mem_ctx, "%d", EPMAPPER_PORT); return NT_STATUS_OK;
			case NCALRPC: binding->endpoint = EPMAPPER_IDENTIFIER; return NT_STATUS_OK;
			default: return NT_STATUS_NOT_SUPPORTED;
		}
	}
	

	ZERO_STRUCT(epmapper_binding);
	epmapper_binding.transport = binding->transport;
	epmapper_binding.host = binding->host;
	epmapper_binding.options = NULL;
	epmapper_binding.flags = 0;
	epmapper_binding.endpoint = NULL;
	
	status = dcerpc_pipe_connect_b(&p,
					&epmapper_binding,
				   DCERPC_EPMAPPER_UUID,
				   DCERPC_EPMAPPER_VERSION,
				   NULL, NULL, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ZERO_STRUCT(handle);
	ZERO_STRUCT(guid);

	status = GUID_from_string(uuid, &binding->object);
	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	binding->object_version = version;

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
		dcerpc_pipe_close(p);
		return status;
	}
	if (r.out.result != 0 || r.out.num_towers != 1) {
		dcerpc_pipe_close(p);
		return NT_STATUS_PORT_UNREACHABLE;
	}

	twr_r = r.out.towers[0].twr;
	if (!twr_r) {
		dcerpc_pipe_close(p);
		return NT_STATUS_PORT_UNREACHABLE;
	}

	if (twr_r->tower.num_floors != twr.tower.num_floors ||
	    twr_r->tower.floors[3].lhs.protocol != twr.tower.floors[3].lhs.protocol) {
		dcerpc_pipe_close(p);
		return NT_STATUS_PORT_UNREACHABLE;
	}

	binding->endpoint = dcerpc_floor_get_rhs_data(mem_ctx, &twr_r->tower.floors[3]);

	dcerpc_pipe_close(p);

	return NT_STATUS_OK;
}


/* open a rpc connection to a rpc pipe on SMB using the binding
   structure to determine the endpoint and options */
static NTSTATUS dcerpc_pipe_connect_ncacn_np(struct dcerpc_pipe **p, 
					     struct dcerpc_binding *binding,
					     const char *pipe_uuid, 
					     uint32_t pipe_version,
					     const char *domain,
					     const char *username,
					     const char *password)
{
	NTSTATUS status;
	BOOL retry;
	struct smbcli_state *cli;
	const char *pipe_name;
	TALLOC_CTX *mem_ctx = talloc_init("dcerpc_pipe_connect_ncacn_np");
	
	if (!binding->endpoint) {
		const struct dcerpc_interface_table *table = idl_iface_by_uuid(pipe_uuid);
		struct dcerpc_binding default_binding;
		int i;

		if (!table) {
			DEBUG(0,("Unknown interface endpoint '%s'\n", pipe_uuid));
			talloc_destroy(mem_ctx);
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* Find one of the default pipes for this interface */
		for (i = 0; i < table->endpoints->count; i++) {
			status = dcerpc_parse_binding(mem_ctx, table->endpoints->names[i], &default_binding);

			if (NT_STATUS_IS_OK(status) && default_binding.transport == NCACN_NP) {
				pipe_name = default_binding.endpoint;	
				break;
				
			}
		}
	} else {
		pipe_name = binding->endpoint;
	}

	if (!strncasecmp(pipe_name, "/pipe/", 6) || 
		!strncasecmp(pipe_name, "\\pipe\\", 6)) {
		pipe_name+=6;
	}

	if (pipe_name[0] != '\\') {
		pipe_name = talloc_asprintf(mem_ctx, "\\%s", pipe_name);
	}
	
	if (!username || !username[0]) {
		status = smbcli_full_connection(NULL, &cli, lp_netbios_name(),
					     binding->host, NULL, 
					     "ipc$", "?????", 
					     "", "", NULL, 0, &retry);
	} else {
		status = smbcli_full_connection(NULL, &cli, lp_netbios_name(),
					     binding->host, NULL, 
					     "ipc$", "?????", 
					     username, domain,
					     password, 0, &retry);
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to connect to %s - %s\n", binding->host, nt_errstr(status)));
		talloc_destroy(mem_ctx);
		return status;
	}

	status = dcerpc_pipe_open_smb(p, cli->tree, pipe_name);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to open pipe %s - %s\n", pipe_name, nt_errstr(status)));
		smbcli_tdis(cli);
		smbcli_shutdown(cli);
		talloc_destroy(mem_ctx);
        return status;
    }	

	talloc_destroy(mem_ctx);
	
	/* this ensures that the reference count is decremented so
	   a pipe close will really close the link */
	talloc_steal(*p, cli);

	(*p)->flags = binding->flags;

	/* remember the binding string for possible secondary connections */
	(*p)->binding_string = dcerpc_binding_string((*p), binding);

	if (username && username[0] && (binding->flags & DCERPC_SCHANNEL_ANY)) {
		status = dcerpc_bind_auth_schannel(*p, pipe_uuid, pipe_version, 
						   domain, username, password);
	} else if (username && username[0] &&
		   (binding->flags & (DCERPC_CONNECT|DCERPC_SIGN|DCERPC_SEAL))) {
		status = dcerpc_bind_auth_ntlm(*p, pipe_uuid, pipe_version, domain, username, password);
	} else {    
		status = dcerpc_bind_auth_none(*p, pipe_uuid, pipe_version);

	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to uuid %s - %s\n", pipe_uuid, nt_errstr(status)));
		dcerpc_pipe_close(*p);
		*p = NULL;
		return status;
	}

	return NT_STATUS_OK;
}

/* open a rpc connection to a rpc pipe on SMP using the binding
   structure to determine the endpoint and options */
static NTSTATUS dcerpc_pipe_connect_ncalrpc(struct dcerpc_pipe **p, 
						 struct dcerpc_binding *binding,
						 const char *pipe_uuid, 
						 uint32_t pipe_version,
						 const char *domain,
						 const char *username,
						 const char *password)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_init("dcerpc_pipe_connect_ncalrpc");

	/* Look up identifier using the epmapper */
	if (!binding->endpoint) {
		status = dcerpc_epm_map_binding(mem_ctx, binding, pipe_uuid, pipe_version);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Failed to map DCERPC/TCP NCALRPC identifier for '%s' - %s\n", 
				 pipe_uuid, nt_errstr(status)));
			talloc_destroy(mem_ctx);
			return status;
		}
		DEBUG(1,("Mapped to DCERPC/TCP identifier %s\n", binding->endpoint));
	}

	status = dcerpc_pipe_open_pipe(p, binding->endpoint);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to open ncalrpc pipe '%s'\n", binding->endpoint));
		talloc_destroy(mem_ctx);
   		return status;
    }

	(*p)->flags = binding->flags;

	/* remember the binding string for possible secondary connections */
	(*p)->binding_string = dcerpc_binding_string((*p), binding);

	if (username && username[0] && (binding->flags & DCERPC_SCHANNEL_ANY)) {
		status = dcerpc_bind_auth_schannel(*p, pipe_uuid, pipe_version, 
						   domain, username, password);
	} else if (username && username[0]) {
		status = dcerpc_bind_auth_ntlm(*p, pipe_uuid, pipe_version, domain, username, password);
	} else {    
		status = dcerpc_bind_auth_none(*p, pipe_uuid, pipe_version);
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to uuid %s - %s\n", 
			 pipe_uuid, nt_errstr(status)));
		dcerpc_pipe_close(*p);
		*p = NULL;
		talloc_destroy(mem_ctx);
		return status;
	}
 
	talloc_destroy(mem_ctx);
    return status;
}



/* open a rpc connection to a rpc pipe on SMP using the binding
   structure to determine the endpoint and options */
static NTSTATUS dcerpc_pipe_connect_ncacn_unix_stream(struct dcerpc_pipe **p, 
						 struct dcerpc_binding *binding,
						 const char *pipe_uuid, 
						 uint32_t pipe_version,
						 const char *domain,
						 const char *username,
						 const char *password)
{
	NTSTATUS status;

	if (!binding->endpoint) {
		DEBUG(0, ("Path to unix socket not specified\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = dcerpc_pipe_open_unix_stream(p, binding->endpoint);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to open unix socket %s\n", binding->endpoint));
                return status;
    }

	(*p)->flags = binding->flags;

	/* remember the binding string for possible secondary connections */
	(*p)->binding_string = dcerpc_binding_string((*p), binding);

	if (username && username[0] && (binding->flags & DCERPC_SCHANNEL_ANY)) {
		status = dcerpc_bind_auth_schannel(*p, pipe_uuid, pipe_version, 
						   domain, username, password);
	} else if (username && username[0]) {
		status = dcerpc_bind_auth_ntlm(*p, pipe_uuid, pipe_version, domain, username, password);
	} else {    
		status = dcerpc_bind_auth_none(*p, pipe_uuid, pipe_version);
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to uuid %s - %s\n", 
			 pipe_uuid, nt_errstr(status)));
		dcerpc_pipe_close(*p);
		*p = NULL;
		return status;
	}
 
    return status;
}

/* open a rpc connection to a rpc pipe on SMP using the binding
   structure to determine the endpoint and options */
static NTSTATUS dcerpc_pipe_connect_ncacn_ip_tcp(struct dcerpc_pipe **p, 
						 struct dcerpc_binding *binding,
						 const char *pipe_uuid, 
						 uint32_t pipe_version,
						 const char *domain,
						 const char *username,
						 const char *password)
{
	NTSTATUS status;
	uint32_t port = 0;
	TALLOC_CTX *mem_ctx = talloc_init("connect_ncacn_ip_tcp");

	if (!binding->endpoint) {
		status = dcerpc_epm_map_binding(mem_ctx, binding, 
						 pipe_uuid, pipe_version);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Failed to map DCERPC/TCP port for '%s' - %s\n", 
				 pipe_uuid, nt_errstr(status)));
			return status;
		}
		DEBUG(1,("Mapped to DCERPC/TCP port %s\n", binding->endpoint));
	}

	port = atoi(binding->endpoint);

	status = dcerpc_pipe_open_tcp(p, binding->host, port, AF_UNSPEC);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to connect to %s:%d\n", binding->host, port));
                return status;
        }

	(*p)->flags = binding->flags;

	/* remember the binding string for possible secondary connections */
	(*p)->binding_string = dcerpc_binding_string((*p), binding);

	if (username && username[0] && (binding->flags & DCERPC_SCHANNEL_ANY)) {
		status = dcerpc_bind_auth_schannel(*p, pipe_uuid, pipe_version, 
						   domain, username, password);
	} else if (username && username[0]) {
		status = dcerpc_bind_auth_ntlm(*p, pipe_uuid, pipe_version, domain, username, password);
	} else {    
		status = dcerpc_bind_auth_none(*p, pipe_uuid, pipe_version);
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to uuid %s - %s\n", 
			 pipe_uuid, nt_errstr(status)));
		dcerpc_pipe_close(*p);
		*p = NULL;
		return status;
	}
 
        return status;
}


/* open a rpc connection to a rpc pipe, using the specified 
   binding structure to determine the endpoint and options */
NTSTATUS dcerpc_pipe_connect_b(struct dcerpc_pipe **p, 
			       struct dcerpc_binding *binding,
			       const char *pipe_uuid, 
			       uint32_t pipe_version,
			       const char *domain,
			       const char *username,
			       const char *password)
{
	NTSTATUS status = NT_STATUS_INVALID_PARAMETER;

	switch (binding->transport) {
	case NCACN_NP:
		status = dcerpc_pipe_connect_ncacn_np(p, binding, pipe_uuid, pipe_version,
						      domain, username, password);
		break;
	case NCACN_IP_TCP:
		status = dcerpc_pipe_connect_ncacn_ip_tcp(p, binding, pipe_uuid, pipe_version,
							  domain, username, password);
		break;
	case NCACN_UNIX_STREAM:
		status = dcerpc_pipe_connect_ncacn_unix_stream(p, binding, pipe_uuid, pipe_version, domain, username, password);
		break;
	case NCALRPC:
		status = dcerpc_pipe_connect_ncalrpc(p, binding, pipe_uuid, pipe_version, domain, username, password);
		break;
	default:
		return NT_STATUS_NOT_SUPPORTED;
	}

	return status;
}


/* open a rpc connection to a rpc pipe, using the specified string
   binding to determine the endpoint and options */
NTSTATUS dcerpc_pipe_connect(struct dcerpc_pipe **p, 
			     const char *binding,
			     const char *pipe_uuid, 
			     uint32_t pipe_version,
			     const char *domain,
			     const char *username,
			     const char *password)
{
	struct dcerpc_binding b;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("dcerpc_pipe_connect");
	if (!mem_ctx) return NT_STATUS_NO_MEMORY;

	status = dcerpc_parse_binding(mem_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to parse dcerpc binding '%s'\n", binding));
		talloc_destroy(mem_ctx);
		return status;
	}

	DEBUG(3,("Using binding %s\n", dcerpc_binding_string(mem_ctx, &b)));

	status = dcerpc_pipe_connect_b(p, &b, pipe_uuid, pipe_version, domain, username, password);

	talloc_destroy(mem_ctx);
	return status;
}


/*
  create a secondary dcerpc connection from a primary connection

  if the primary is a SMB connection then the secondary connection
  will be on the same SMB connection, but use a new fnum
*/
NTSTATUS dcerpc_secondary_connection(struct dcerpc_pipe *p, struct dcerpc_pipe **p2,
				     const char *pipe_name,
				     const char *pipe_uuid,
				     uint32_t pipe_version)
{
	struct smbcli_tree *tree;
	NTSTATUS status = NT_STATUS_INVALID_PARAMETER;
	struct dcerpc_binding b;

	switch (p->transport.transport) {
	case NCACN_NP:
		tree = dcerpc_smb_tree(p);
		if (!tree) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		status = dcerpc_pipe_open_smb(p2, tree, pipe_name);
		break;

	case NCACN_IP_TCP:
		status = dcerpc_parse_binding(p, p->binding_string, &b);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		b.flags &= ~DCERPC_AUTH_OPTIONS;
		status = dcerpc_pipe_connect_ncacn_ip_tcp(p2, &b, pipe_uuid,
							  pipe_version, NULL, 
							  NULL, NULL);
		break;
	default:
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	(*p2)->flags = p->flags;

	status = dcerpc_bind_auth_none(*p2, pipe_uuid, pipe_version);
	if (!NT_STATUS_IS_OK(status)) {
                return status;
        }

	return NT_STATUS_OK;
}

NTSTATUS dcerpc_generic_session_key(struct dcerpc_pipe *p,
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
	return p->security_state.session_key(p, session_key);
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
		if (!file_exist(name, NULL)) {
			if (file_save(name, pkt->data, pkt->length)) {
				DEBUG(10,("Logged rpc packet to %s\n", name));
			}
			free(name);
			break;
		}
		free(name);
	}
}

