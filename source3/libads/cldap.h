#ifndef __LIBADS_CLDAP_H__
#define __LIBADS_CLDAP_H__

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

/* The following definitions come from libads/cldap.c  */
bool ads_cldap_netlogon(TALLOC_CTX *mem_ctx,
			const char *server,
			const char *realm,
			uint32_t nt_version,
			struct netlogon_samlogon_response **reply);
bool ads_cldap_netlogon_5(TALLOC_CTX *mem_ctx,
			  const char *server,
			  const char *realm,
			  struct NETLOGON_SAM_LOGON_RESPONSE_EX *reply5);
#endif
