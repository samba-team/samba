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
#include "../auth/ntlmssp/ntlmssp.h"
#include "../auth/ntlmssp/ntlmssp_private.h"

static void debug_ntlmssp_flags_raw(int level, uint32_t flags)
{
#define _PRINT_FLAG_LINE(v) do { \
	if (flags & (v)) { \
		DEBUGADD(level, ("  " #v "\n")); \
	} \
} while (0)
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_UNICODE);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_OEM);
	_PRINT_FLAG_LINE(NTLMSSP_REQUEST_TARGET);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_SIGN);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_SEAL);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_DATAGRAM);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_LM_KEY);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_NETWARE);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_NTLM);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_NT_ONLY);
	_PRINT_FLAG_LINE(NTLMSSP_ANONYMOUS);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_THIS_IS_LOCAL_CALL);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_ALWAYS_SIGN);
	_PRINT_FLAG_LINE(NTLMSSP_TARGET_TYPE_DOMAIN);
	_PRINT_FLAG_LINE(NTLMSSP_TARGET_TYPE_SERVER);
	_PRINT_FLAG_LINE(NTLMSSP_TARGET_TYPE_SHARE);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_IDENTIFY);
	_PRINT_FLAG_LINE(NTLMSSP_REQUEST_NON_NT_SESSION_KEY);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_TARGET_INFO);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_VERSION);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_128);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_KEY_EXCH);
	_PRINT_FLAG_LINE(NTLMSSP_NEGOTIATE_56);
}

/**
 * Print out the NTLMSSP flags for debugging
 * @param neg_flags The flags from the packet
 */
void debug_ntlmssp_flags(uint32_t neg_flags)
{
	DEBUG(3,("Got NTLMSSP neg_flags=0x%08x\n", neg_flags));
	debug_ntlmssp_flags_raw(4, neg_flags);
}

void ntlmssp_handle_neg_flags(struct ntlmssp_state *ntlmssp_state,
			      uint32_t neg_flags, bool allow_lm)
{
	if (neg_flags & NTLMSSP_NEGOTIATE_UNICODE) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_UNICODE;
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_OEM;
		ntlmssp_state->unicode = true;
	} else {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_UNICODE;
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_OEM;
		ntlmssp_state->unicode = false;
	}

	if ((neg_flags & NTLMSSP_NEGOTIATE_LM_KEY) && allow_lm) {
		/* other end forcing us to use LM */
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_LM_KEY;
		ntlmssp_state->use_ntlmv2 = false;
	} else {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	}

	if (!(neg_flags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
	}

	if (!(neg_flags & NTLMSSP_NEGOTIATE_NTLM2)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_NTLM2;
	}

	if (!(neg_flags & NTLMSSP_NEGOTIATE_128)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_128;
	}

	if (!(neg_flags & NTLMSSP_NEGOTIATE_56)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_56;
	}

	if (!(neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_KEY_EXCH;
	}

	if (!(neg_flags & NTLMSSP_NEGOTIATE_SIGN)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_SIGN;
	}

	if (!(neg_flags & NTLMSSP_NEGOTIATE_SEAL)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_SEAL;
	}

	if (!(neg_flags & NTLMSSP_NEGOTIATE_VERSION)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_VERSION;
	}

	if ((neg_flags & NTLMSSP_REQUEST_TARGET)) {
		ntlmssp_state->neg_flags |= NTLMSSP_REQUEST_TARGET;
	}
}

/* Does this blob looks like it could be NTLMSSP? */
bool ntlmssp_blob_matches_magic(const DATA_BLOB *blob)
{
	if (blob->length > 8 && memcmp("NTLMSSP\0", blob->data, 8) == 0) {
		return true;
	} else {
		return false;
	}
}
