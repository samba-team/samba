/* 
   Unix SMB/CIFS implementation.

   dcerpc utility functions

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Jelmer Vernooij 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Rafal Szczesniak 2006
   Copyright (C) Stefan Metzmacher 2014

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "../../lib/util/util_net.h"
#include "librpc/gen_ndr/ndr_epmapper.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/rpc/dcerpc.h"
#include "rpc_common.h"

#undef strcasecmp
#undef strncasecmp

#define MAX_PROTSEQ		10

struct dcerpc_binding {
	enum dcerpc_transport_t transport;
	struct GUID object;
	const char *object_string;
	const char *host;
	const char *target_hostname;
	const char *target_principal;
	const char *endpoint;
	const char **options;
	uint32_t flags;
	uint32_t assoc_group_id;
	char assoc_group_string[11]; /* 0x3456789a + '\0' */
};

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
		{ EPM_PROTOCOL_NCALRPC, EPM_PROTOCOL_NAMED_PIPE } },
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

static const struct ncacn_option {
	const char *name;
	uint32_t flag;
} ncacn_options[] = {
	{"sign", DCERPC_SIGN},
	{"seal", DCERPC_SEAL},
	{"connect", DCERPC_CONNECT},
	{"spnego", DCERPC_AUTH_SPNEGO},
	{"ntlm", DCERPC_AUTH_NTLM},
	{"krb5", DCERPC_AUTH_KRB5},
	{"schannel", DCERPC_SCHANNEL | DCERPC_SCHANNEL_AUTO},
	{"validate", DCERPC_DEBUG_VALIDATE_BOTH},
	{"print", DCERPC_DEBUG_PRINT_BOTH},
	{"padcheck", DCERPC_DEBUG_PAD_CHECK},
	{"bigendian", DCERPC_PUSH_BIGENDIAN},
	{"smb1", DCERPC_SMB1},
	{"smb2", DCERPC_SMB2},
	{"ndr64", DCERPC_NDR64},
	{"packet", DCERPC_PACKET},
};

static const struct ncacn_option *ncacn_option_by_name(const char *name)
{
	size_t i;

	for (i=0; i<ARRAY_SIZE(ncacn_options); i++) {
		int ret;

		ret = strcasecmp(ncacn_options[i].name, name);
		if (ret != 0) {
			continue;
		}

		return &ncacn_options[i];
	}

	return NULL;
}

const char *epm_floor_string(TALLOC_CTX *mem_ctx, struct epm_floor *epm_floor)
{
	struct ndr_syntax_id syntax;
	NTSTATUS status;

	switch(epm_floor->lhs.protocol) {
		case EPM_PROTOCOL_UUID:
			status = dcerpc_floor_get_lhs_data(epm_floor, &syntax);
			if (NT_STATUS_IS_OK(status)) {
				/* lhs is used: UUID */
				char *uuidstr;

				if (GUID_equal(&syntax.uuid, &ndr_transfer_syntax_ndr.uuid)) {
					return "NDR";
				} 

				if (GUID_equal(&syntax.uuid, &ndr_transfer_syntax_ndr64.uuid)) {
					return "NDR64";
				} 

				uuidstr = GUID_string(mem_ctx, &syntax.uuid);

				return talloc_asprintf(mem_ctx, " uuid %s/0x%02x", uuidstr, syntax.if_version);
			} else { /* IPX */
				return talloc_asprintf(mem_ctx, "IPX:%s", 
						data_blob_hex_string_upper(mem_ctx, &epm_floor->rhs.uuid.unknown));
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

		case EPM_PROTOCOL_NAMED_PIPE:
			return talloc_asprintf(mem_ctx, "NAMED-PIPE:%s", epm_floor->rhs.named_pipe.path);

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
_PUBLIC_ char *dcerpc_binding_string(TALLOC_CTX *mem_ctx, const struct dcerpc_binding *b)
{
	char *s = talloc_strdup(mem_ctx, "");
	char *o = s;
	int i;
	const char *t_name = NULL;
	bool option_section = false;
	const char *target_hostname = NULL;

	if (b->transport != NCA_UNKNOWN) {
		t_name = derpc_transport_string_by_transport(b->transport);
		if (!t_name) {
			talloc_free(o);
			return NULL;
		}
	}

	if (!GUID_all_zero(&b->object)) {
		o = s;
		s = talloc_asprintf_append_buffer(s, "%s@",
				    GUID_string(mem_ctx, &b->object));
		if (s == NULL) {
			talloc_free(o);
			return NULL;
		}
	}

	if (t_name != NULL) {
		o = s;
		s = talloc_asprintf_append_buffer(s, "%s:", t_name);
		if (s == NULL) {
			talloc_free(o);
			return NULL;
		}
	}

	if (b->host) {
		o = s;
		s = talloc_asprintf_append_buffer(s, "%s", b->host);
		if (s == NULL) {
			talloc_free(o);
			return NULL;
		}
	}

	target_hostname = b->target_hostname;
	if (target_hostname != NULL && b->host != NULL) {
		if (strcmp(target_hostname, b->host) == 0) {
			target_hostname = NULL;
		}
	}

	if (b->endpoint) {
		option_section = true;
	} else if (target_hostname) {
		option_section = true;
	} else if (b->target_principal) {
		option_section = true;
	} else if (b->assoc_group_id != 0) {
		option_section = true;
	} else if (b->options) {
		option_section = true;
	} else if (b->flags) {
		option_section = true;
	}

	if (!option_section) {
		return s;
	}

	o = s;
	s = talloc_asprintf_append_buffer(s, "[");
	if (s == NULL) {
		talloc_free(o);
		return NULL;
	}

	if (b->endpoint) {
		o = s;
		s = talloc_asprintf_append_buffer(s, "%s", b->endpoint);
		if (s == NULL) {
			talloc_free(o);
			return NULL;
		}
	}

	for (i=0;i<ARRAY_SIZE(ncacn_options);i++) {
		if (!(b->flags & ncacn_options[i].flag)) {
			continue;
		}

		o = s;
		s = talloc_asprintf_append_buffer(s, ",%s", ncacn_options[i].name);
		if (s == NULL) {
			talloc_free(o);
			return NULL;
		}
	}

	if (target_hostname) {
		o = s;
		s = talloc_asprintf_append_buffer(s, ",target_hostname=%s",
						  b->target_hostname);
		if (s == NULL) {
			talloc_free(o);
			return NULL;
		}
	}

	if (b->target_principal) {
		o = s;
		s = talloc_asprintf_append_buffer(s, ",target_principal=%s",
						  b->target_principal);
		if (s == NULL) {
			talloc_free(o);
			return NULL;
		}
	}

	if (b->assoc_group_id != 0) {
		o = s;
		s = talloc_asprintf_append_buffer(s, ",assoc_group_id=0x%08x",
						  b->assoc_group_id);
		if (s == NULL) {
			talloc_free(o);
			return NULL;
		}
	}

	for (i=0;b->options && b->options[i];i++) {
		o = s;
		s = talloc_asprintf_append_buffer(s, ",%s", b->options[i]);
		if (s == NULL) {
			talloc_free(o);
			return NULL;
		}
	}

	o = s;
	s = talloc_asprintf_append_buffer(s, "]");
	if (s == NULL) {
		talloc_free(o);
		return NULL;
	}

	return s;
}

/*
  parse a binding string into a dcerpc_binding structure
*/
_PUBLIC_ NTSTATUS dcerpc_parse_binding(TALLOC_CTX *mem_ctx, const char *_s, struct dcerpc_binding **b_out)
{
	char *_t;
	struct dcerpc_binding *b;
	char *s;
	char *options = NULL;
	char *p;
	size_t i;
	NTSTATUS status;

	b = talloc_zero(mem_ctx, struct dcerpc_binding);
	if (!b) {
		return NT_STATUS_NO_MEMORY;
	}

	_t = talloc_strdup(b, _s);
	if (_t == NULL) {
		talloc_free(b);
		return NT_STATUS_NO_MEMORY;
	}

	s = _t;

	p = strchr(s, '[');
	if (p) {
		*p = '\0';
		options = p + 1;
		if (options[strlen(options)-1] != ']') {
			talloc_free(b);
			return NT_STATUS_INVALID_PARAMETER_MIX;
		}
		options[strlen(options)-1] = 0;
	}

	p = strchr(s, '@');

	if (p && PTR_DIFF(p, s) == 36) { /* 36 is the length of a UUID */
		*p = '\0';

		status = dcerpc_binding_set_string_option(b, "object", s);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(b);
			return status;
		}

		s = p + 1;
	}

	p = strchr(s, ':');

	if (p == NULL) {
		b->transport = NCA_UNKNOWN;
	} else if (is_ipaddress_v6(s)) {
		b->transport = NCA_UNKNOWN;
	} else {
		*p = '\0';

		status = dcerpc_binding_set_string_option(b, "transport", s);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(b);
			return status;
		}

		s = p + 1;
	}

	if (strlen(s) > 0) {
		status = dcerpc_binding_set_string_option(b, "host", s);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(b);
			return status;
		}

		b->target_hostname = talloc_strdup(b, b->host);
		if (b->target_hostname == NULL) {
			talloc_free(b);
			return NT_STATUS_NO_MEMORY;
		}
	}

	for (i=0; options != NULL; i++) {
		const char *name = options;
		const char *value = NULL;

		p = strchr(options, ',');
		if (p != NULL) {
			*p = '\0';
			options = p+1;
		} else {
			options = NULL;
		}

		p = strchr(name, '=');
		if (p != NULL) {
			*p = '\0';
			value = p + 1;
		}

		if (value == NULL) {
			/*
			 * If it's not a key=value pair
			 * it might be a ncacn_option
			 * or if it's the first option
			 * it's the endpoint.
			 */
			const struct ncacn_option *no = NULL;

			value = name;

			no = ncacn_option_by_name(name);
			if (no == NULL) {
				if (i > 0) {
					/*
					 * we don't allow unknown options
					 */
					return NT_STATUS_INVALID_PARAMETER_MIX;
				}

				/*
				 * This is the endpoint
				 */
				name = "endpoint";
				if (strlen(value) == 0) {
					value = NULL;
				}
			}
		}

		status = dcerpc_binding_set_string_option(b, name, value);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(b);
			return status;
		}
	}

	talloc_free(_t);
	*b_out = b;
	return NT_STATUS_OK;
}

_PUBLIC_ struct GUID dcerpc_binding_get_object(const struct dcerpc_binding *b)
{
	return b->object;
}

_PUBLIC_ NTSTATUS dcerpc_binding_set_object(struct dcerpc_binding *b,
					    struct GUID object)
{
	char *tmp = discard_const_p(char, b->object_string);

	if (GUID_all_zero(&object)) {
		talloc_free(tmp);
		b->object_string = NULL;
		ZERO_STRUCT(b->object);
		return NT_STATUS_OK;
	}

	b->object_string = GUID_string(b, &object);
	if (b->object_string == NULL) {
		b->object_string = tmp;
		return NT_STATUS_NO_MEMORY;
	}
	talloc_free(tmp);

	b->object = object;
	return NT_STATUS_OK;
}

_PUBLIC_ enum dcerpc_transport_t dcerpc_binding_get_transport(const struct dcerpc_binding *b)
{
	return b->transport;
}

_PUBLIC_ NTSTATUS dcerpc_binding_set_transport(struct dcerpc_binding *b,
					       enum dcerpc_transport_t transport)
{
	NTSTATUS status;

	/*
	 * TODO: we may want to check the transport value is
	 * wellknown.
	 */
	if (b->transport == transport) {
		return NT_STATUS_OK;
	}

	/*
	 * This implicitly resets the endpoint
	 * as the endpoint is transport specific.
	 *
	 * It also resets the assoc group as it's
	 * also endpoint specific.
	 *
	 * TODO: in future we may reset more options
	 * here.
	 */
	status = dcerpc_binding_set_string_option(b, "endpoint", NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	b->assoc_group_id = 0;

	b->transport = transport;
	return NT_STATUS_OK;
}

_PUBLIC_ void dcerpc_binding_get_auth_info(const struct dcerpc_binding *b,
					   enum dcerpc_AuthType *_auth_type,
					   enum dcerpc_AuthLevel *_auth_level)
{
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	if (b->flags & DCERPC_AUTH_SPNEGO) {
		auth_type = DCERPC_AUTH_TYPE_SPNEGO;
	} else if (b->flags & DCERPC_AUTH_KRB5) {
		auth_type = DCERPC_AUTH_TYPE_KRB5;
	} else if (b->flags & DCERPC_SCHANNEL) {
		auth_type = DCERPC_AUTH_TYPE_SCHANNEL;
	} else if (b->flags & DCERPC_AUTH_NTLM) {
		auth_type = DCERPC_AUTH_TYPE_NTLMSSP;
	} else {
		auth_type = DCERPC_AUTH_TYPE_NONE;
	}

	if (b->flags & DCERPC_SEAL) {
		auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
	} else if (b->flags & DCERPC_SIGN) {
		auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
	} else if (b->flags & DCERPC_CONNECT) {
		auth_level = DCERPC_AUTH_LEVEL_CONNECT;
	} else if (b->flags & DCERPC_PACKET) {
		auth_level = DCERPC_AUTH_LEVEL_PACKET;
	} else if (auth_type != DCERPC_AUTH_TYPE_NONE) {
		auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
	} else {
		auth_level = DCERPC_AUTH_LEVEL_NONE;
	}

	if (_auth_type != NULL) {
		*_auth_type = auth_type;
	}

	if (_auth_level != NULL) {
		*_auth_level = auth_level;
	}
}

_PUBLIC_ uint32_t dcerpc_binding_get_assoc_group_id(const struct dcerpc_binding *b)
{
	return b->assoc_group_id;
}

_PUBLIC_ NTSTATUS dcerpc_binding_set_assoc_group_id(struct dcerpc_binding *b,
						    uint32_t assoc_group_id)
{
	b->assoc_group_id = assoc_group_id;
	return NT_STATUS_OK;
}

_PUBLIC_ struct ndr_syntax_id dcerpc_binding_get_abstract_syntax(const struct dcerpc_binding *b)
{
	const char *s = dcerpc_binding_get_string_option(b, "abstract_syntax");
	bool ok;
	struct ndr_syntax_id id;

	if (s == NULL) {
		return ndr_syntax_id_null;
	}

	ok = ndr_syntax_id_from_string(s, &id);
	if (!ok) {
		return ndr_syntax_id_null;
	}

	return id;
}

_PUBLIC_ NTSTATUS dcerpc_binding_set_abstract_syntax(struct dcerpc_binding *b,
						     const struct ndr_syntax_id *syntax)
{
	NTSTATUS status;
	char *s = NULL;

	if (syntax == NULL) {
		status = dcerpc_binding_set_string_option(b, "abstract_syntax", NULL);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		return NT_STATUS_OK;
	}

	if (ndr_syntax_id_equal(&ndr_syntax_id_null, syntax)) {
		status = dcerpc_binding_set_string_option(b, "abstract_syntax", NULL);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		return NT_STATUS_OK;
	}

	s = ndr_syntax_id_to_string(b, syntax);
	if (s == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dcerpc_binding_set_string_option(b, "abstract_syntax", s);
	TALLOC_FREE(s);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

_PUBLIC_ const char *dcerpc_binding_get_string_option(const struct dcerpc_binding *b,
						      const char *name)
{
	struct {
		const char *name;
		const char *value;
#define _SPECIAL(x) { .name = #x, .value = b->x, }
	} specials[] = {
		{ .name = "object", .value = b->object_string, },
		_SPECIAL(host),
		_SPECIAL(endpoint),
		_SPECIAL(target_hostname),
		_SPECIAL(target_principal),
#undef _SPECIAL
	};
	const struct ncacn_option *no = NULL;
	size_t name_len = strlen(name);
	size_t i;
	int ret;

	ret = strcmp(name, "transport");
	if (ret == 0) {
		return derpc_transport_string_by_transport(b->transport);
	}

	ret = strcmp(name, "assoc_group_id");
	if (ret == 0) {
		char *tmp = discard_const_p(char, b->assoc_group_string);

		if (b->assoc_group_id == 0) {
			return NULL;
		}

		snprintf(tmp, sizeof(b->assoc_group_string),
			 "0x%08x", b->assoc_group_id);
		return (const char *)b->assoc_group_string;
	}

	for (i=0; i < ARRAY_SIZE(specials); i++) {
		ret = strcmp(specials[i].name, name);
		if (ret != 0) {
			continue;
		}

		return specials[i].value;
	}

	no = ncacn_option_by_name(name);
	if (no != NULL) {
		if (b->flags & no->flag) {
			return no->name;
		}

		return NULL;
	}

	if (b->options == NULL) {
		return NULL;
	}

	for (i=0; b->options[i]; i++) {
		const char *o = b->options[i];
		const char *vs = NULL;

		ret = strncmp(name, o, name_len);
		if (ret != 0) {
			continue;
		}

		if (o[name_len] != '=') {
			continue;
		}

		vs = &o[name_len + 1];

		return vs;
	}

	return NULL;
}

_PUBLIC_ char *dcerpc_binding_copy_string_option(TALLOC_CTX *mem_ctx,
						 const struct dcerpc_binding *b,
						 const char *name)
{
	const char *c = dcerpc_binding_get_string_option(b, name);
	char *v;

	if (c == NULL) {
		errno = ENOENT;
		return NULL;
	}

	v = talloc_strdup(mem_ctx, c);
	if (v == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	return v;
}

_PUBLIC_ NTSTATUS dcerpc_binding_set_string_option(struct dcerpc_binding *b,
						   const char *name,
						   const char *value)
{
	struct {
		const char *name;
		const char **ptr;
#define _SPECIAL(x) { .name = #x, .ptr = &b->x, }
	} specials[] = {
		_SPECIAL(host),
		_SPECIAL(endpoint),
		_SPECIAL(target_hostname),
		_SPECIAL(target_principal),
#undef _SPECIAL
	};
	const struct ncacn_option *no = NULL;
	size_t name_len = strlen(name);
	const char *opt = NULL;
	char *tmp;
	size_t i;
	int ret;

	/*
	 * Note: value == NULL, means delete it.
	 * value != NULL means add or reset.
	 */

	ret = strcmp(name, "transport");
	if (ret == 0) {
		enum dcerpc_transport_t t = dcerpc_transport_by_name(value);

		if (t == NCA_UNKNOWN && value != NULL) {
			return NT_STATUS_INVALID_PARAMETER_MIX;
		}

		return dcerpc_binding_set_transport(b, t);
	}

	ret = strcmp(name, "object");
	if (ret == 0) {
		NTSTATUS status;
		struct GUID uuid = GUID_zero();

		if (value != NULL) {
			DATA_BLOB blob;
			blob = data_blob_string_const(value);
			if (blob.length != 36) {
				return NT_STATUS_INVALID_PARAMETER_MIX;
			}

			status = GUID_from_data_blob(&blob, &uuid);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}

		return dcerpc_binding_set_object(b, uuid);
	}

	ret = strcmp(name, "assoc_group_id");
	if (ret == 0) {
		uint32_t assoc_group_id = 0;

		if (value != NULL) {
			char c;

			ret = sscanf(value, "0x%08x%c", &assoc_group_id, &c);
			if (ret != 1) {
				return NT_STATUS_INVALID_PARAMETER_MIX;
			}
		}

		return dcerpc_binding_set_assoc_group_id(b, assoc_group_id);
	}

	for (i=0; i < ARRAY_SIZE(specials); i++) {
		ret = strcmp(specials[i].name, name);
		if (ret != 0) {
			continue;
		}

		tmp = discard_const_p(char, *specials[i].ptr);

		if (value == NULL) {
			talloc_free(tmp);
			*specials[i].ptr = NULL;
			return NT_STATUS_OK;
		}

		if (value[0] == '\0') {
			return NT_STATUS_INVALID_PARAMETER_MIX;
		}

		*specials[i].ptr = talloc_strdup(b, value);
		if (*specials[i].ptr == NULL) {
			*specials[i].ptr = tmp;
			return NT_STATUS_NO_MEMORY;
		}
		talloc_free(tmp);

		return NT_STATUS_OK;
	}

	no = ncacn_option_by_name(name);
	if (no != NULL) {
		if (value == NULL) {
			b->flags &= ~no->flag;
			return NT_STATUS_OK;
		}

		ret = strcasecmp(no->name, value);
		if (ret != 0) {
			return NT_STATUS_INVALID_PARAMETER_MIX;
		}

		b->flags |= no->flag;
		return NT_STATUS_OK;
	}

	for (i=0; b->options && b->options[i]; i++) {
		const char *o = b->options[i];

		ret = strncmp(name, o, name_len);
		if (ret != 0) {
			continue;
		}

		if (o[name_len] != '=') {
			continue;
		}

		opt = o;
		break;
	}

	if (opt == NULL) {
		const char **n;

		if (value == NULL) {
			return NT_STATUS_OK;
		}

		n = talloc_realloc(b, b->options, const char *, i + 2);
		if (n == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		n[i] = NULL;
		n[i + 1] = NULL;
		b->options = n;
	}

	tmp = discard_const_p(char, opt);

	if (value == NULL) {
		for (;b->options[i];i++) {
			b->options[i] = b->options[i+1];
		}
		talloc_free(tmp);
		return NT_STATUS_OK;
	}

	b->options[i] = talloc_asprintf(b->options, "%s=%s",
					name, value);
	if (b->options[i] == NULL) {
		b->options[i] = tmp;
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

_PUBLIC_ uint32_t dcerpc_binding_get_flags(const struct dcerpc_binding *b)
{
	return b->flags;
}

_PUBLIC_ NTSTATUS dcerpc_binding_set_flags(struct dcerpc_binding *b,
					   uint32_t additional,
					   uint32_t clear)
{
	/*
	 * TODO: in future we may want to reject invalid combinations
	 */
	b->flags &= ~clear;
	b->flags |= additional;

	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS dcerpc_floor_get_lhs_data(const struct epm_floor *epm_floor,
					    struct ndr_syntax_id *syntax)
{
	TALLOC_CTX *mem_ctx = talloc_init("floor_get_lhs_data");
	struct ndr_pull *ndr;
	enum ndr_err_code ndr_err;
	uint16_t if_version=0;

	ndr = ndr_pull_init_blob(&epm_floor->lhs.lhs_data, mem_ctx);
	if (ndr == NULL) {
		talloc_free(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	ndr->flags |= LIBNDR_FLAG_NOALIGN;

	ndr_err = ndr_pull_GUID(ndr, NDR_SCALARS | NDR_BUFFERS, &syntax->uuid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(mem_ctx);
		return ndr_map_error2ntstatus(ndr_err);
	}

	ndr_err = ndr_pull_uint16(ndr, NDR_SCALARS, &if_version);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(mem_ctx);
		return ndr_map_error2ntstatus(ndr_err);
	}

	syntax->if_version = if_version;

	talloc_free(mem_ctx);

	return NT_STATUS_OK;
}

static DATA_BLOB dcerpc_floor_pack_lhs_data(TALLOC_CTX *mem_ctx, const struct ndr_syntax_id *syntax)
{
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	struct ndr_push *ndr;

	ndr = ndr_push_init_ctx(mem_ctx);
	if (ndr == NULL) {
		return data_blob_null;
	}

	ndr->flags |= LIBNDR_FLAG_NOALIGN;

	ndr_err = ndr_push_GUID(ndr, NDR_SCALARS | NDR_BUFFERS, &syntax->uuid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return data_blob_null;
	}
	ndr_err = ndr_push_uint16(ndr, NDR_SCALARS, syntax->if_version);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return data_blob_null;
	}

	blob = ndr_push_blob(ndr);
	talloc_steal(mem_ctx, blob.data);
	talloc_free(ndr);
	return blob;
}

static bool dcerpc_floor_pack_rhs_if_version_data(
	TALLOC_CTX *mem_ctx, const struct ndr_syntax_id *syntax,
	DATA_BLOB *pblob)
{
	DATA_BLOB blob;
	struct ndr_push *ndr = ndr_push_init_ctx(mem_ctx);
	enum ndr_err_code ndr_err;

	if (ndr == NULL) {
		return false;
	}

	ndr->flags |= LIBNDR_FLAG_NOALIGN;

	ndr_err = ndr_push_uint16(ndr, NDR_SCALARS, syntax->if_version >> 16);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	blob = ndr_push_blob(ndr);
	talloc_steal(mem_ctx, blob.data);
	talloc_free(ndr);
	*pblob = blob;
	return true;
}

char *dcerpc_floor_get_rhs_data(TALLOC_CTX *mem_ctx, struct epm_floor *epm_floor)
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

	case EPM_PROTOCOL_NAMED_PIPE:
		if (strlen(epm_floor->rhs.named_pipe.path) == 0) return NULL;
		return talloc_strdup(mem_ctx, epm_floor->rhs.named_pipe.path);

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

static NTSTATUS dcerpc_floor_set_rhs_data(TALLOC_CTX *mem_ctx, 
					  struct epm_floor *epm_floor,  
					  const char *data)
{
	if (data == NULL) {
		data = "";
	}

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
		if (!is_ipaddress_v4(data)) {
			data = "0.0.0.0";
		}
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

	case EPM_PROTOCOL_NAMED_PIPE:
		epm_floor->rhs.named_pipe.path = talloc_strdup(mem_ctx, data);
		NT_STATUS_HAVE_NO_MEMORY(epm_floor->rhs.named_pipe.path);
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
	return (unsigned int)-1;
}

_PUBLIC_ enum dcerpc_transport_t dcerpc_transport_by_tower(const struct epm_tower *tower)
{
	int i;

	/* Find a transport that matches this tower */
	for (i=0;i<ARRAY_SIZE(transports);i++) {
		int j;
		if (transports[i].num_protocols != tower->num_floors - 2) {
			continue; 
		}

		for (j = 0; j < transports[i].num_protocols && j < MAX_PROTSEQ; j++) {
			if (transports[i].protseq[j] != tower->floors[j+2].lhs.protocol) {
				break;
			}
		}

		if (j == transports[i].num_protocols) {
			return transports[i].transport;
		}
	}

	/* Unknown transport */
	return (unsigned int)-1;
}

_PUBLIC_ const char *derpc_transport_string_by_transport(enum dcerpc_transport_t t)
{
	int i;

	for (i=0; i<ARRAY_SIZE(transports); i++) {
		if (t == transports[i].transport) {
			return transports[i].name;
		}
	}
	return NULL;
}

_PUBLIC_ enum dcerpc_transport_t dcerpc_transport_by_name(const char *name)
{
	size_t i;

	if (name == NULL) {
		return NCA_UNKNOWN;
	}

	for (i=0; i<ARRAY_SIZE(transports);i++) {
		if (strcasecmp(name, transports[i].name) == 0) {
			return transports[i].transport;
		}
	}

	return NCA_UNKNOWN;
}

_PUBLIC_ NTSTATUS dcerpc_binding_from_tower(TALLOC_CTX *mem_ctx,
					    struct epm_tower *tower,
					    struct dcerpc_binding **b_out)
{
	NTSTATUS status;
	struct dcerpc_binding *b;
	enum dcerpc_transport_t transport;
	struct ndr_syntax_id abstract_syntax;
	char *endpoint = NULL;
	char *host = NULL;

	/*
	 * A tower needs to have at least 4 floors to carry useful
	 * information. Floor 3 is the transport identifier which defines
	 * how many floors are required at least.
	 */
	if (tower->num_floors < 4) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = dcerpc_parse_binding(mem_ctx, "", &b);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	transport = dcerpc_transport_by_tower(tower);
	if (transport == NCA_UNKNOWN) {
		talloc_free(b);
		return NT_STATUS_NOT_SUPPORTED;
	}

	status = dcerpc_binding_set_transport(b, transport);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(b);
		return status;
	}

	/* Set abstract syntax */
	status = dcerpc_floor_get_lhs_data(&tower->floors[0], &abstract_syntax);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(b);
		return status;
	}

	status = dcerpc_binding_set_abstract_syntax(b, &abstract_syntax);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(b);
		return status;
	}

	/* Ignore floor 1, it contains the NDR version info */

	/* Set endpoint */
	errno = 0;
	if (tower->num_floors >= 4) {
		endpoint = dcerpc_floor_get_rhs_data(b, &tower->floors[3]);
	}
	if (errno != 0) {
		int saved_errno = errno;
		talloc_free(b);
		return map_nt_error_from_unix_common(saved_errno);
	}

	status = dcerpc_binding_set_string_option(b, "endpoint", endpoint);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(b);
		return status;
	}
	TALLOC_FREE(endpoint);

	/* Set network address */
	errno = 0;
	if (tower->num_floors >= 5) {
		host = dcerpc_floor_get_rhs_data(b, &tower->floors[4]);
	}
	if (errno != 0) {
		int saved_errno = errno;
		talloc_free(b);
		return map_nt_error_from_unix_common(saved_errno);
	}

	status = dcerpc_binding_set_string_option(b, "host", host);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(b);
		return status;
	}
	status = dcerpc_binding_set_string_option(b, "target_hostname", host);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(b);
		return status;
	}
	TALLOC_FREE(host);

	*b_out = b;
	return NT_STATUS_OK;
}

_PUBLIC_ struct dcerpc_binding *dcerpc_binding_dup(TALLOC_CTX *mem_ctx,
						   const struct dcerpc_binding *b)
{
	struct dcerpc_binding *n;
	uint32_t count;

	n = talloc_zero(mem_ctx, struct dcerpc_binding);
	if (n == NULL) {
		return NULL;
	}

	n->transport = b->transport;
	n->object = b->object;
	n->flags = b->flags;
	n->assoc_group_id = b->assoc_group_id;

	if (b->object_string != NULL) {
		n->object_string = talloc_strdup(n, b->object_string);
		if (n->object_string == NULL) {
			talloc_free(n);
			return NULL;
		}
	}
	if (b->host != NULL) {
		n->host = talloc_strdup(n, b->host);
		if (n->host == NULL) {
			talloc_free(n);
			return NULL;
		}
	}

	if (b->target_hostname != NULL) {
		n->target_hostname = talloc_strdup(n, b->target_hostname);
		if (n->target_hostname == NULL) {
			talloc_free(n);
			return NULL;
		}
	}

	if (b->target_principal != NULL) {
		n->target_principal = talloc_strdup(n, b->target_principal);
		if (n->target_principal == NULL) {
			talloc_free(n);
			return NULL;
		}
	}

	if (b->endpoint != NULL) {
		n->endpoint = talloc_strdup(n, b->endpoint);
		if (n->endpoint == NULL) {
			talloc_free(n);
			return NULL;
		}
	}

	for (count = 0; b->options && b->options[count]; count++);

	if (count > 0) {
		uint32_t i;

		n->options = talloc_array(n, const char *, count + 1);
		if (n->options == NULL) {
			talloc_free(n);
			return NULL;
		}

		for (i = 0; i < count; i++) {
			n->options[i] = talloc_strdup(n->options, b->options[i]);
			if (n->options[i] == NULL) {
				talloc_free(n);
				return NULL;
			}
		}
		n->options[count] = NULL;
	}

	return n;
}

_PUBLIC_ NTSTATUS dcerpc_binding_build_tower(TALLOC_CTX *mem_ctx,
					     const struct dcerpc_binding *binding,
					     struct epm_tower *tower)
{
	const enum epm_protocol *protseq = NULL;
	int num_protocols = -1, i;
	struct ndr_syntax_id abstract_syntax;
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

	abstract_syntax = dcerpc_binding_get_abstract_syntax(binding);
	tower->floors[0].lhs.lhs_data = dcerpc_floor_pack_lhs_data(tower->floors,
								   &abstract_syntax);

	if (!dcerpc_floor_pack_rhs_if_version_data(
		    tower->floors, &abstract_syntax,
		    &tower->floors[0].rhs.uuid.unknown)) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Floor 1 */
	tower->floors[1].lhs.protocol = EPM_PROTOCOL_UUID;

	tower->floors[1].lhs.lhs_data = dcerpc_floor_pack_lhs_data(tower->floors, 
								&ndr_transfer_syntax_ndr);

	tower->floors[1].rhs.uuid.unknown = data_blob_talloc_zero(tower->floors, 2);

	/* Floor 2 to num_protocols */
	for (i = 0; i < num_protocols; i++) {
		tower->floors[2 + i].lhs.protocol = protseq[i];
		tower->floors[2 + i].lhs.lhs_data = data_blob_null;
		ZERO_STRUCT(tower->floors[2 + i].rhs);
		status = dcerpc_floor_set_rhs_data(tower->floors,
						   &tower->floors[2 + i],
						   NULL);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	/* The 4th floor contains the endpoint */
	if (num_protocols >= 2 && binding->endpoint) {
		status = dcerpc_floor_set_rhs_data(tower->floors,
						   &tower->floors[3],
						   binding->endpoint);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	/* The 5th contains the network address */
	if (num_protocols >= 3 && binding->host) {
		status = dcerpc_floor_set_rhs_data(tower->floors,
						   &tower->floors[4],
						   binding->host);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}
