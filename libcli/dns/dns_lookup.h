/*
 *  Unix SMB/CIFS implementation.
 *  Internal DNS query structures
 *  Copyright (C) Volker Lendecke 2018
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIBCLI_DNS_DNS_LOOKUP_H__
#define __LIBCLI_DNS_DNS_LOOKUP_H__

#include "replace.h"
#include "system/network.h"
#include <tevent.h>
#include "lib/util/data_blob.h"
#include "lib/util/time.h"
#include "librpc/gen_ndr/dns.h"

struct tevent_req *dns_lookup_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   FILE *resolv_conf_fp,
				   const char *name,
				   enum dns_qclass qclass,
				   enum dns_qtype qtype);
int dns_lookup_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		    struct dns_name_packet **reply);
int dns_lookup(FILE *resolv_conf_fp,
	       const char *name,
	       enum dns_qclass qclass,
	       enum dns_qtype qtype,
	       TALLOC_CTX *mem_ctx,
	       struct dns_name_packet **reply);

bool dns_res_rec_get_sockaddr(const struct dns_res_rec *rec,
			      struct sockaddr_storage *addr);

#endif
