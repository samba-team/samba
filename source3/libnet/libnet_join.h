#ifndef __LIBNET_LIBNET_JOIN_H__
#define __LIBNET_LIBNET_JOIN_H__

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

/* The following definitions come from libnet/libnet_join.c  */

NTSTATUS libnet_join_ok(const char *netbios_domain_name,
			const char *machine_name,
			const char *dc_name);
WERROR libnet_init_JoinCtx(TALLOC_CTX *mem_ctx,
			   struct libnet_JoinCtx **r);
WERROR libnet_init_UnjoinCtx(TALLOC_CTX *mem_ctx,
			     struct libnet_UnjoinCtx **r);
WERROR libnet_Join(TALLOC_CTX *mem_ctx,
		   struct libnet_JoinCtx *r);
WERROR libnet_Unjoin(TALLOC_CTX *mem_ctx,
		     struct libnet_UnjoinCtx *r);
#endif
