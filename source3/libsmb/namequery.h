/*
 * Unix SMB/CIFS implementation.
 * Copyright (C) Volker Lendecke 2018
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIBSMB_NAMEQUERY_H__
#define __LIBSMB_NAMEQUERY_H__

#include "includes.h"
#include <tevent.h>

/* The following definitions come from libsmb/namequery.c  */

bool saf_store( const char *domain, const char *servername );
bool saf_join_store( const char *domain, const char *servername );
bool saf_delete( const char *domain );
char *saf_fetch(TALLOC_CTX *mem_ctx, const char *domain );
struct tevent_req *node_status_query_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct nmb_name *name,
					  const struct sockaddr_storage *addr);
NTSTATUS node_status_query_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				struct node_status **pnode_status,
				int *pnum_names,
				struct node_status_extra *extra);
NTSTATUS node_status_query(TALLOC_CTX *mem_ctx, struct nmb_name *name,
			   const struct sockaddr_storage *addr,
			   struct node_status **pnode_status,
			   int *pnum_names,
			   struct node_status_extra *extra);
bool name_status_find(const char *q_name,
			int q_type,
			int type,
			const struct sockaddr_storage *to_ss,
			fstring name);
int remove_duplicate_addrs2(struct ip_service *iplist, int count );
struct tevent_req *name_query_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   const char *name, int name_type,
				   bool bcast, bool recurse,
				   const struct sockaddr_storage *addr);
NTSTATUS name_query_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			 struct sockaddr_storage **addrs, int *num_addrs,
			 uint8_t *flags);
NTSTATUS name_query(const char *name, int name_type,
		    bool bcast, bool recurse,
		    const struct sockaddr_storage *to_ss,
		    TALLOC_CTX *mem_ctx,
		    struct sockaddr_storage **addrs,
		    int *num_addrs, uint8_t *flags);
struct tevent_req *name_resolve_bcast_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   const char *name,
					   int name_type);
NTSTATUS name_resolve_bcast_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				 struct sockaddr_storage **addrs,
				 int *num_addrs);
NTSTATUS name_resolve_bcast(const char *name,
			int name_type,
			TALLOC_CTX *mem_ctx,
			struct sockaddr_storage **return_iplist,
			int *return_count);
struct tevent_req *resolve_wins_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     const char *name,
				     int name_type);
NTSTATUS resolve_wins_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct sockaddr_storage **addrs,
			   int *num_addrs, uint8_t *flags);
NTSTATUS resolve_wins(const char *name,
		int name_type,
		TALLOC_CTX *mem_ctx,
		struct sockaddr_storage **return_iplist,
		int *return_count);
NTSTATUS internal_resolve_name(const char *name,
			        int name_type,
				const char *sitename,
				struct ip_service **return_iplist,
				int *return_count,
				const char **resolve_order);
bool resolve_name(const char *name,
		struct sockaddr_storage *return_ss,
		int name_type,
		bool prefer_ipv4);
NTSTATUS resolve_name_list(TALLOC_CTX *ctx,
		const char *name,
		int name_type,
		struct sockaddr_storage **return_ss_arr,
		unsigned int *p_num_entries);
bool find_master_ip(const char *group, struct sockaddr_storage *master_ss);
bool get_pdc_ip(const char *domain, struct sockaddr_storage *pss);
NTSTATUS get_sorted_dc_list( const char *domain,
			const char *sitename,
			struct ip_service **ip_list,
			int *count,
			bool ads_only );
NTSTATUS get_kdc_list( const char *realm,
			const char *sitename,
			struct ip_service **ip_list,
			int *count);

#endif
