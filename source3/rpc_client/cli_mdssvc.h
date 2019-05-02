/*
   Unix SMB/CIFS implementation.
   mdssvc client functions

   Copyright (C) Ralph Boehme			2019

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

#ifndef _MDSCLI_H_
#define _MDSCLI_H_

struct mdscli_ctx;
struct mdscli_search_ctx;

struct mdsctx_id mdscli_new_ctx_id(struct mdscli_ctx *mdscli_ctx);
char *mdscli_get_basepath(TALLOC_CTX *mem_ctx,
			  struct mdscli_ctx *mdscli_ctx);
struct mdscli_ctx *mdscli_search_get_ctx(struct mdscli_search_ctx *search);

struct tevent_req *mdscli_connect_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct dcerpc_binding_handle *bh,
				       const char *share_name,
				       const char *mount_path);
NTSTATUS mdscli_connect_recv(struct tevent_req *req,
			     TALLOC_CTX *mem_ctx,
			     struct mdscli_ctx **mdscli_ctx);
NTSTATUS mdscli_connect(TALLOC_CTX *mem_ctx,
			struct dcerpc_binding_handle *bh,
			const char *share_name,
			const char *mount_path,
			struct mdscli_ctx **mdscli_ctx);

struct tevent_req *mdscli_search_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct mdscli_ctx *mdscli_ctx,
				      const char *mds_query,
				      const char *path_scope,
				      bool live);
NTSTATUS mdscli_search_recv(struct tevent_req *req,
			    TALLOC_CTX *mem_ctx,
			    struct mdscli_search_ctx **search);
NTSTATUS mdscli_search(TALLOC_CTX *mem_ctx,
		       struct mdscli_ctx *mdscli_ctx,
		       const char *mds_query,
		       const char *path_scope,
		       bool live,
		       struct mdscli_search_ctx **search);

struct tevent_req *mdscli_get_results_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct mdscli_search_ctx *search);
NTSTATUS mdscli_get_results_recv(struct tevent_req *req,
				 TALLOC_CTX *mem_ctx,
				 uint64_t **cnids);
NTSTATUS mdscli_get_results(TALLOC_CTX *mem_ctx,
			    struct mdscli_search_ctx *search,
			    uint64_t **_cnids);

struct tevent_req *mdscli_get_path_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct mdscli_ctx *mdscli_ctx,
					uint64_t cnid);
NTSTATUS mdscli_get_path_recv(struct tevent_req *req,
			      TALLOC_CTX *mem_ctx,
			      char **path);
NTSTATUS mdscli_get_path(TALLOC_CTX *mem_ctx,
			 struct mdscli_ctx *mdscli_ctx,
			 uint64_t cnid,
			 char **path);

struct tevent_req *mdscli_close_search_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct mdscli_search_ctx **_search);
NTSTATUS mdscli_close_search_recv(struct tevent_req *req);
NTSTATUS mdscli_close_search(struct mdscli_search_ctx **search);

struct tevent_req *mdscli_disconnect_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct mdscli_ctx *mdscli_ctx);
NTSTATUS mdscli_disconnect_recv(struct tevent_req *req);
NTSTATUS mdscli_disconnect(struct mdscli_ctx *mdscli_ctx);

#endif /* _MDSCLI_H_ */
