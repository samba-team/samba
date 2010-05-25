/*
   Unix SMB/Netbios implementation.
   Version 3.0
   handle NLTMSSP, server side

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett 2001-2003
   Copyright (C) Andrew Bartlett 2005 (Updated from gensec).

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
 * Print out the NTLMSSP flags for debugging
 * @param neg_flags The flags from the packet
 */
void debug_ntlmssp_flags(uint32_t neg_flags)
{
	DEBUG(3,("Got NTLMSSP neg_flags=0x%08x\n", neg_flags));

	if (neg_flags & NTLMSSP_NEGOTIATE_UNICODE)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_UNICODE\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_OEM)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_OEM\n"));
	if (neg_flags & NTLMSSP_REQUEST_TARGET)
		DEBUGADD(4, ("  NTLMSSP_REQUEST_TARGET\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_SIGN)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_SIGN\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_SEAL)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_SEAL\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_DATAGRAM)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_DATAGRAM\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_LM_KEY)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_LM_KEY\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_NETWARE)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_NETWARE\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_NTLM)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_NTLM\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_THIS_IS_LOCAL_CALL)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_THIS_IS_LOCAL_CALL\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_ALWAYS_SIGN\n"));
	if (neg_flags & NTLMSSP_REQUEST_NON_NT_SESSION_KEY)
		DEBUGADD(4, ("  NTLMSSP_REQUEST_NON_NT_SESSION_KEY\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_NTLM2)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_NTLM2\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_TARGET_INFO)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_TARGET_INFO\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_VERSION)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_VERSION\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_128)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_128\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_KEY_EXCH\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_56)
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_56\n"));
}
