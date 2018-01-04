/*
   Unix SMB/CIFS implementation.

   Small async DNS library for Samba with socketwrapper support

   Copyright (C) 2012 Kai Blin  <kai@samba.org>

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

#ifndef __LIBDNS_H__
#define __LIBDNS_H__

#include "lib/util/data_blob.h"
#include "lib/util/time.h"
#include "librpc/gen_ndr/dns.h"

/*
 * DNS request with fallback to TCP on truncation
 */

struct tevent_req *dns_cli_request_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const char *nameserver,
					const char *name,
					enum dns_qclass qclass,
					enum dns_qtype qtype);
int dns_cli_request_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			 struct dns_name_packet **reply);


#endif /*__LIBDNS_H__*/
