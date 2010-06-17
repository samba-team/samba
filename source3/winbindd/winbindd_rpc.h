/*
 * Unix SMB/CIFS implementation.
 *
 * Winbind rpc backend functions
 *
 * Copyright (c) 2000-2003 Tim Potter
 * Copyright (c) 2001      Andrew Tridgell
 * Copyright (c) 2005      Volker Lendecke
 * Copyright (c) 2008      Guenther Deschner (pidl conversion)
 * Copyright (c) 2010      Andreas Schneider <asn@samba.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _WINBINDD_RPC_H_
#define _WINBINDD_RPC_H_

/* Query display info for a domain */
NTSTATUS rpc_query_user_list(TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client *samr_pipe,
			     struct policy_handle *samr_policy,
			     const struct dom_sid *domain_sid,
			     uint32_t *pnum_info,
			     struct wbint_userinfo **pinfo);

NTSTATUS rpc_enum_dom_groups(TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client *samr_pipe,
			     struct policy_handle *sam_policy,
			     uint32_t *pnum_info,
			     struct acct_info **pinfo);

/* List all domain groups */
NTSTATUS rpc_enum_local_groups(TALLOC_CTX *mem_ctx,
			       struct rpc_pipe_client *samr_pipe,
			       struct policy_handle *samr_policy,
			       uint32_t *pnum_info,
			       struct acct_info **pinfo);

/* Convert a single name to a sid in a domain */
NTSTATUS rpc_name_to_sid(TALLOC_CTX *mem_ctx,
			 struct rpc_pipe_client *lsa_pipe,
			 struct policy_handle *lsa_policy,
			 const char *domain_name,
			 const char *name,
			 uint32_t flags,
			 struct dom_sid *psid,
			 enum lsa_SidType *ptype);

#endif /* _WINBINDD_RPC_H_ */
