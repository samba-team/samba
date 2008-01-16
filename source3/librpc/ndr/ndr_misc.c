/* 
   Unix SMB/CIFS implementation.

   UUID/GUID/policy_handle functions

   Copyright (C) Theodore Ts'o               1996, 1997,
   Copyright (C) Jim McDonough                     2002.
   Copyright (C) Andrew Tridgell                   2003.
   Copyright (C) Stefan (metze) Metzmacher         2004.
   
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

enum ndr_err_code ndr_push_GUID(struct ndr_push *ndr, int ndr_flags, const struct GUID *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->time_low));
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->time_mid));
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->time_hi_and_version));
		NDR_CHECK(ndr_push_array_uint8(ndr, NDR_SCALARS, r->clock_seq, 2));
		NDR_CHECK(ndr_push_array_uint8(ndr, NDR_SCALARS, r->node, 6));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_GUID(struct ndr_pull *ndr, int ndr_flags, struct GUID *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->time_low));
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->time_mid));
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->time_hi_and_version));
		NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->clock_seq, 2));
		NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->node, 6));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

size_t ndr_size_GUID(const struct GUID *r, int flags)
{
	return ndr_size_struct(r, flags, (ndr_push_flags_fn_t)ndr_push_GUID);
}

/**
 * see if a range of memory is all zero. A NULL pointer is considered
 * to be all zero 
 */
bool all_zero(const uint8_t *ptr, size_t size)
{
	int i;
	if (!ptr) return True;
	for (i=0;i<size;i++) {
		if (ptr[i]) return False;
	}
	return True;
}

void ndr_print_GUID(struct ndr_print *ndr, const char *name, const struct GUID *guid)
{
	ndr->print(ndr, "%-25s: %s", name, GUID_string(ndr, guid));
}

enum ndr_err_code ndr_push_policy_handle(struct ndr_push *ndr, int ndr_flags, const struct policy_handle *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->handle_type));
		NDR_CHECK(ndr_push_GUID(ndr, NDR_SCALARS, &r->uuid));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_policy_handle(struct ndr_pull *ndr, int ndr_flags, struct policy_handle *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->handle_type));
		NDR_CHECK(ndr_pull_GUID(ndr, NDR_SCALARS, &r->uuid));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_policy_handle(struct ndr_print *ndr, const char *name, const struct policy_handle *r)
{
	ndr_print_struct(ndr, name, "policy_handle");
	ndr->depth++;
	ndr_print_uint32(ndr, "handle_type", r->handle_type);
	ndr_print_GUID(ndr, "uuid", &r->uuid);
	ndr->depth--;
}

enum ndr_err_code ndr_push_server_id(struct ndr_push *ndr, int ndr_flags, const struct server_id *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS,
					  (uint32_t)r->pid));
#ifdef CLUSTER_SUPPORT
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS,
					  (uint32_t)r->vnn));
#endif
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_server_id(struct ndr_pull *ndr, int ndr_flags, struct server_id *r)
{
	if (ndr_flags & NDR_SCALARS) {
		uint32_t pid;
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &pid));
#ifdef CLUSTER_SUPPORT
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->vnn));
#endif
		r->pid = (pid_t)pid;
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_server_id(struct ndr_print *ndr, const char *name, const struct server_id *r)
{
	ndr_print_struct(ndr, name, "server_id");
	ndr->depth++;
	ndr_print_uint32(ndr, "id", (uint32_t)r->pid);
#ifdef CLUSTER_SUPPORT
	ndr_print_uint32(ndr, "vnn", (uint32_t)r->vnn);
#endif
	ndr->depth--;
}

void ndr_print_ads_struct(struct ndr_print *ndr, const char *name, const struct ads_struct *r)
{
	if (!r) { return; }

	ndr_print_struct(ndr, name, "ads_struct");
	ndr->depth++;
	ndr_print_bool(ndr, "is_mine", r->is_mine);
	ndr_print_struct(ndr, name, "server");
	ndr->depth++;
	ndr_print_string(ndr, "realm", r->server.realm);
	ndr_print_string(ndr, "workgroup", r->server.workgroup);
	ndr_print_string(ndr, "ldap_server", r->server.ldap_server);
	ndr_print_bool(ndr, "foreign", r->server.foreign);
	ndr->depth--;
	ndr_print_struct(ndr, name, "auth");
	ndr->depth++;
	ndr_print_string(ndr, "realm", r->auth.realm);
#ifdef DEBUG_PASSWORD
	ndr_print_string(ndr, "password", r->auth.password);
#else
	ndr_print_string(ndr, "password", "(PASSWORD ommited)");
#endif
	ndr_print_string(ndr, "user_name", r->auth.user_name);
	ndr_print_string(ndr, "kdc_server", r->auth.kdc_server);
	ndr_print_uint32(ndr, "flags", r->auth.flags);
	ndr_print_uint32(ndr, "time_offset", r->auth.time_offset);
	ndr_print_time_t(ndr, "tgt_expire", r->auth.tgt_expire);
	ndr_print_time_t(ndr, "tgs_expire", r->auth.tgs_expire);
	ndr_print_time_t(ndr, "renewable", r->auth.renewable);
	ndr->depth--;
	ndr_print_struct(ndr, name, "config");
	ndr->depth++;
	ndr_print_uint32(ndr, "flags", r->config.flags);
	ndr_print_string(ndr, "realm", r->config.realm);
	ndr_print_string(ndr, "bind_path", r->config.bind_path);
	ndr_print_string(ndr, "ldap_server_name", r->config.ldap_server_name);
	ndr_print_string(ndr, "server_site_name", r->config.server_site_name);
	ndr_print_string(ndr, "client_site_name", r->config.client_site_name);
	ndr_print_time_t(ndr, "current_time", r->config.current_time);
	ndr_print_bool(ndr, "tried_closest_dc", r->config.tried_closest_dc);
	ndr_print_string(ndr, "schema_path", r->config.schema_path);
	ndr_print_string(ndr, "config_path", r->config.config_path);
	ndr->depth--;
#ifdef HAVE_LDAP
	ndr_print_struct(ndr, name, "ldap");
	ndr->depth++;
	ndr_print_ptr(ndr, "ld", r->ldap.ld);
	ndr_print_sockaddr_storage(ndr, "ss", &r->ldap.ss);
	ndr_print_time_t(ndr, "last_attempt", r->ldap.last_attempt);
	ndr_print_uint32(ndr, "port", r->ldap.port);
	ndr_print_uint16(ndr, "wrap_type", r->ldap.wrap_type);
#ifdef HAVE_LDAP_SASL_WRAPPING
	ndr_print_ptr(ndr, "sbiod", r->ldap.sbiod);
#endif /* HAVE_LDAP_SASL_WRAPPING */
	ndr_print_ptr(ndr, "mem_ctx", r->ldap.mem_ctx);
	ndr_print_ptr(ndr, "wrap_ops", r->ldap.wrap_ops);
	ndr_print_ptr(ndr, "wrap_private_data", r->ldap.wrap_private_data);
	ndr_print_struct(ndr, name, "in");
	ndr->depth++;
	ndr_print_uint32(ndr, "ofs", r->ldap.in.ofs);
	ndr_print_uint32(ndr, "needed", r->ldap.in.needed);
	ndr_print_uint32(ndr, "left", r->ldap.in.left);
	ndr_print_uint32(ndr, "max_wrapped", r->ldap.in.max_wrapped);
	ndr_print_uint32(ndr, "min_wrapped", r->ldap.in.min_wrapped);
	ndr_print_uint32(ndr, "size", r->ldap.in.size);
	ndr_print_array_uint8(ndr, "buf", r->ldap.in.buf, r->ldap.in.size);
	ndr->depth--;
	ndr_print_struct(ndr, name, "out");
	ndr->depth++;
	ndr_print_uint32(ndr, "ofs", r->ldap.out.ofs);
	ndr_print_uint32(ndr, "left", r->ldap.out.left);
	ndr_print_uint32(ndr, "max_unwrapped", r->ldap.out.max_unwrapped);
	ndr_print_uint32(ndr, "sig_size", r->ldap.out.sig_size);
	ndr_print_uint32(ndr, "size", r->ldap.out.size);
	ndr_print_array_uint8(ndr, "buf", r->ldap.out.buf, r->ldap.out.size);
	ndr->depth--;
	ndr->depth--;
#endif /* HAVE_LDAP */
	ndr->depth--;
}
