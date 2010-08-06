/*
   Unix SMB/Netbios implementation.
   Version 3.0
   handle NLTMSSP, server side

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett 2001-2010

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

#include "includes.h"
#include "../libcli/auth/ntlmssp.h"
#include "../libcli/auth/ntlmssp_private.h"

/**
 * Determine correct target name flags for reply, given server role
 * and negotiated flags
 *
 * @param ntlmssp_state NTLMSSP State
 * @param neg_flags The flags from the packet
 * @param chal_flags The flags to be set in the reply packet
 * @return The 'target name' string.
 */

const char *ntlmssp_target_name(struct ntlmssp_state *ntlmssp_state,
				uint32_t neg_flags, uint32_t *chal_flags)
{
	if (neg_flags & NTLMSSP_REQUEST_TARGET) {
		*chal_flags |= NTLMSSP_NEGOTIATE_TARGET_INFO;
		*chal_flags |= NTLMSSP_REQUEST_TARGET;
		if (ntlmssp_state->server.is_standalone) {
			*chal_flags |= NTLMSSP_TARGET_TYPE_SERVER;
			return ntlmssp_state->server.netbios_name;
		} else {
			*chal_flags |= NTLMSSP_TARGET_TYPE_DOMAIN;
			return ntlmssp_state->server.netbios_domain;
		};
	} else {
		return "";
	}
}
