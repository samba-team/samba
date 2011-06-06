#ifndef __LIBSMB_CLIDGRAM_H__
#define __LIBSMB_CLIDGRAM_H__

/*
   Unix SMB/CIFS implementation.

   (C) 2011 Samba Team.

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

#include "../libcli/netlogon/netlogon.h"

/* The following definitions come from libsmb/clidgram.c  */

struct tevent_req *nbt_getdc_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct messaging_context *msg_ctx,
				  const struct sockaddr_storage *dc_addr,
				  const char *domain_name,
				  const struct dom_sid *sid,
				  uint32_t nt_version);
NTSTATUS nbt_getdc_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			uint32_t *nt_version, const char **dc_name,
			struct netlogon_samlogon_response **samlogon_response);
NTSTATUS nbt_getdc(struct messaging_context *msg_ctx,
		   const struct sockaddr_storage *dc_addr,
		   const char *domain_name,
		   const struct dom_sid *sid,
		   uint32_t nt_version,
		   TALLOC_CTX *mem_ctx,
		   uint32_t *pnt_version,
		   const char **dc_name,
		   struct netlogon_samlogon_response **samlogon_response);
#endif
