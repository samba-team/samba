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
  work out what TCP port to use for a given interface on a given host
*/
NTSTATUS dcerpc_epm_map_tcp_port(const char *server, 
				 const char *uuid, uint_t version,
				 uint32_t *port)
{
	struct dcerpc_pipe *p;
	NTSTATUS status;
	struct epm_Map r;
	struct policy_handle handle;
	struct GUID guid;
	struct epm_twr_t twr, *twr_r;

	if (strcasecmp(uuid, DCERPC_EPMAPPER_UUID) == 0 ||
	    strcasecmp(uuid, DCERPC_MGMT_UUID) == 0) {
		/* don't lookup epmapper via epmapper! */
		*port = EPMAPPER_PORT;
		return NT_STATUS_OK;
	}

	status = dcerpc_pipe_open_tcp(&p, server, EPMAPPER_PORT, AF_UNSPEC );
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* we can use the pipes memory context here as we will have a short
	   lived connection */
	status = dcerpc_bind_byuuid(p, p, 
				    DCERPC_EPMAPPER_UUID,
				    DCERPC_EPMAPPER_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		dcerpc_pipe_close(p);
		return status;
	}

	ZERO_STRUCT(handle);
	ZERO_STRUCT(guid);

	twr.towers.num_floors = 5;
	twr.towers.floors = talloc(p, sizeof(twr.towers.floors[0]) * 5);

	/* what I'd like for christmas ... */

	/* an RPC interface ... */
	twr.towers.floors[0].lhs.protocol = EPM_PROTOCOL_UUID;
	GUID_from_string(uuid, &twr.towers.floors[0].lhs.info.uuid.uuid);
	twr.towers.floors[0].lhs.info.uuid.version = version;
	twr.towers.floors[0].rhs.uuid.unknown = 0;

	/* encoded with NDR ... */
	twr.towers.floors[1].lhs.protocol = EPM_PROTOCOL_UUID;
	GUID_from_string(NDR_GUID, &twr.towers.floors[1].lhs.info.uuid.uuid);
	twr.towers.floors[1].lhs.info.uuid.version = NDR_GUID_VERSION;
	twr.towers.floors[1].rhs.uuid.unknown = 0;

	/* on an RPC connection ... */
	twr.towers.floors[2].lhs.protocol = EPM_PROTOCOL_NCACN;
	twr.towers.floors[2].lhs.info.lhs_data = data_blob(NULL, 0);
	twr.towers.floors[2].rhs.ncacn.minor_version = 0;

	/* on a TCP port ... */
	twr.towers.floors[3].lhs.protocol = EPM_PROTOCOL_TCP;
	twr.towers.floors[3].lhs.info.lhs_data = data_blob(NULL, 0);
	twr.towers.floors[3].rhs.tcp.port = 0;

	/* on an IP link ... */
	twr.towers.floors[4].lhs.protocol = EPM_PROTOCOL_IP;
	twr.towers.floors[4].lhs.info.lhs_data = data_blob(NULL, 0);
	twr.towers.floors[4].rhs.ip.address = 0;

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

	if (twr_r->towers.num_floors != 5 ||
	    twr_r->towers.floors[3].lhs.protocol != twr.towers.floors[3].lhs.protocol) {
		dcerpc_pipe_close(p);
		return NT_STATUS_PORT_UNREACHABLE;
	}

	*port = twr_r->towers.floors[3].rhs.tcp.port;

	dcerpc_pipe_close(p);

	return NT_STATUS_OK;
}

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


static const struct {
	const char *name;
	enum dcerpc_transport_t transport;
} ncacn_transports[] = {
	{"ncacn_np",     NCACN_NP},
	{"ncacn_ip_tcp", NCACN_IP_TCP}
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

	for (i=0;i<ARRAY_SIZE(ncacn_transports);i++) {
		if (ncacn_transports[i].transport == b->transport) {
			t_name = ncacn_transports[i].name;
		}
	}
	if (!t_name) {
		return NULL;
	}

	if (b->object) { 
		s = talloc_asprintf(mem_ctx, "%s@", GUID_string(mem_ctx, b->object));
	}

	s = talloc_asprintf_append(s, "%s:%s[", t_name, b->host);
	if (!s) return NULL;

	/* this is a *really* inefficent way of dealing with strings,
	   but this is rarely called and the strings are always short,
	   so I don't care */
	for (i=0;b->options && b->options[i];i++) {
		s = talloc_asprintf(mem_ctx, "%s%s,", s, b->options[i]);
		if (!s) return NULL;
	}
	for (i=0;i<ARRAY_SIZE(ncacn_options);i++) {
		if (b->flags & ncacn_options[i].flag) {
			s = talloc_asprintf(mem_ctx, "%s%s,", s, ncacn_options[i].name);
			if (!s) return NULL;
		}
	}
	if (s[strlen(s)-1] == ',') {
		s[strlen(s)-1] = 0;
	}
	s = talloc_asprintf(mem_ctx, "%s]", s);

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

		b->object = talloc_p(mem_ctx, struct GUID);
		
		status = GUID_from_string(s, b->object);

		if (NT_STATUS_IS_ERR(status)) {
			DEBUG(0, ("Failed parsing UUID\n"));
			return status;
		}

		s = p + 1;
	} else {
		b->object = NULL;
	}

	p = strchr(s, ':');
	if (!p) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	type = talloc_strndup(mem_ctx, s, PTR_DIFF(p, s));
	if (!type) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<ARRAY_SIZE(ncacn_transports);i++) {
		if (strcasecmp(type, ncacn_transports[i].name) == 0) {
			b->transport = ncacn_transports[i].transport;
			break;
		}
	}
	if (i==ARRAY_SIZE(ncacn_transports)) {
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
	
	if (!binding->options || !binding->options[0] || !strlen(binding->options[0])) {
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

			if (NT_STATUS_IS_OK(status) && default_binding.transport == ENDPOINT_SMB) {
				pipe_name = default_binding.options[0];	
				break;
				
			}
		}
	} else {
		pipe_name = binding->options[0];
	}

	if (!strncasecmp(pipe_name, "/pipe/", 6) || 
		!strncasecmp(pipe_name, "\\pipe\\", 6)) {
		pipe_name+=6;
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

	if (binding->options && binding->options[0] && strlen(binding->options[0])) {
		port = atoi(binding->options[0]);
	}

	if (port == 0) {
		status = dcerpc_epm_map_tcp_port(binding->host, 
						 pipe_uuid, pipe_version,
						 &port);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Failed to map DCERPC/TCP port for '%s' - %s\n", 
				 pipe_uuid, nt_errstr(status)));
			return status;
		}
		DEBUG(1,("Mapped to DCERPC/TCP port %u\n", port));
	}

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
	session_key->data = discard_const_p(char, "SystemLibraryDTC");
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

