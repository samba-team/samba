/*
 * Samba Unix/Linux SMB client library
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

#ifndef _LIBADS_NETLOGON_PING_H_
#define _LIBADS_NETLOGON_PING_H_

#include "replace.h"
#include "lib/tsocket/tsocket.h"
#include "librpc/gen_ndr/nbt.h"
#include "libcli/util/ntstatus.h"
#include "lib/param/loadparm.h"

struct netlogon_samlogon_response;

struct netlogon_ping_filter {
	unsigned ntversion;
	const char *domain;
	const struct dom_sid *domain_sid;
	const struct GUID *domain_guid;
	const char *hostname;
	const char *user;
	int acct_ctrl;
	uint32_t required_flags;
};

struct tevent_req *netlogon_pings_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       enum client_netlogon_ping_protocol proto,
				       struct tsocket_address **servers,
				       size_t num_servers,
				       struct netlogon_ping_filter filter,
				       size_t min_servers,
				       struct timeval timeout);
NTSTATUS netlogon_pings_recv(struct tevent_req *req,
			     TALLOC_CTX *mem_ctx,
			     struct netlogon_samlogon_response ***responses);
NTSTATUS netlogon_pings(TALLOC_CTX *mem_ctx,
			enum client_netlogon_ping_protocol proto,
			struct tsocket_address **servers,
			int num_servers,
			struct netlogon_ping_filter filter,
			int min_servers,
			struct timeval timeout,
			struct netlogon_samlogon_response ***responses);

#endif /* _LIBADS_NETLOGON_PING_H_ */
