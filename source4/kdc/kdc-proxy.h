/*
   Unix SMB/CIFS implementation.

   KDC related functions

   Copyright (c) 2005-2008 Andrew Bartlett <abartlet@samba.org>
   Copyright (c) 2005             Andrew Tridgell <tridge@samba.org>
   Copyright (c) 2005             Stefan Metzmacher <metze@samba.org>

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

#ifndef _KDC_PROXY_H
#define _KDC_PROXY_H

struct tevent_req *kdc_udp_proxy_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct kdc_server *kdc,
				      uint16_t port,
				      DATA_BLOB in);
NTSTATUS kdc_udp_proxy_recv(struct tevent_req *req,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *out);

struct tevent_req *kdc_tcp_proxy_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct kdc_server *kdc,
				      uint16_t port,
				      DATA_BLOB in);
NTSTATUS kdc_tcp_proxy_recv(struct tevent_req *req,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *out);

#endif /* _KDC_PROXY_H */
