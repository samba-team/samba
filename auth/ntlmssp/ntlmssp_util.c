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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

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

NTSTATUS ntlmssp_handle_neg_flags(struct ntlmssp_state *ntlmssp_state,
				  uint32_t flags, const char *name)
{
	uint32_t missing_flags = ntlmssp_state->required_flags;

	if (ntlmssp_state->use_ntlmv2) {
		/*
		 * Using NTLMv2 as a client implies
		 * using NTLMSSP_NEGOTIATE_NTLM2
		 * (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
		 *
		 * Note that 'use_ntlmv2' is only set
		 * true in the client case.
		 *
		 * Even if the server has a bug and does not announce
		 * it, we need to assume it's present.
		 *
		 * Note that we also have the flag
		 * in ntlmssp_state->required_flags,
		 * see gensec_ntlmssp_client_start().
		 *
		 * See bug #12862.
		 */
		flags |= NTLMSSP_NEGOTIATE_NTLM2;
	}

	if (flags & NTLMSSP_NEGOTIATE_UNICODE) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_UNICODE;
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_OEM;
		ntlmssp_state->unicode = true;
	} else {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_UNICODE;
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_OEM;
		ntlmssp_state->unicode = false;
	}

	/*
	 * NTLMSSP_NEGOTIATE_NTLM2 (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
	 * has priority over NTLMSSP_NEGOTIATE_LM_KEY
	 */
	if (!(flags & NTLMSSP_NEGOTIATE_NTLM2)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_NTLM2;
	}

	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	}

	if (!(flags & NTLMSSP_NEGOTIATE_LM_KEY)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	}

	if (!(flags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
	}

	if (!(flags & NTLMSSP_NEGOTIATE_128)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_128;
	}

	if (!(flags & NTLMSSP_NEGOTIATE_56)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_56;
	}

	if (!(flags & NTLMSSP_NEGOTIATE_KEY_EXCH)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_KEY_EXCH;
	}

	if (!(flags & NTLMSSP_NEGOTIATE_SIGN)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_SIGN;
	}

	if (!(flags & NTLMSSP_NEGOTIATE_SEAL)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_SEAL;
	}

	if ((flags & NTLMSSP_REQUEST_TARGET)) {
		ntlmssp_state->neg_flags |= NTLMSSP_REQUEST_TARGET;
	}

	missing_flags &= ~ntlmssp_state->neg_flags;
	if (missing_flags != 0) {
		HRESULT hres = HRES_SEC_E_UNSUPPORTED_FUNCTION;
		NTSTATUS status = NT_STATUS(HRES_ERROR_V(hres));
		DEBUG(1, ("%s: Got %s flags[0x%08x] "
			  "- possible downgrade detected! "
			  "missing_flags[0x%08x] - %s\n",
			  __func__, name,
			  (unsigned)flags,
			  (unsigned)missing_flags,
			  nt_errstr(status)));
		debug_ntlmssp_flags_raw(1, missing_flags);
		DEBUGADD(4, ("neg_flags[0x%08x]\n",
			     (unsigned)ntlmssp_state->neg_flags));
		debug_ntlmssp_flags_raw(4, ntlmssp_state->neg_flags);
		return status;
	}

	return NT_STATUS_OK;
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

const DATA_BLOB ntlmssp_version_blob(void)
{
	/*
	 * This is a simplified version of
	 *
	 * enum ndr_err_code err;
	 * struct ntlmssp_VERSION vers;
	 *
	 * ZERO_STRUCT(vers);
	 * vers.ProductMajorVersion = NTLMSSP_WINDOWS_MAJOR_VERSION_6;
	 * vers.ProductMinorVersion = NTLMSSP_WINDOWS_MINOR_VERSION_1;
	 * vers.ProductBuild = 0;
	 * vers.NTLMRevisionCurrent = NTLMSSP_REVISION_W2K3;
	 *
	 * err = ndr_push_struct_blob(&version_blob,
	 * 			ntlmssp_state,
	 * 			&vers,
	 * 			(ndr_push_flags_fn_t)ndr_push_ntlmssp_VERSION);
	 *
	 * if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
	 * 	data_blob_free(&struct_blob);
	 * 	return NT_STATUS_NO_MEMORY;
	 * }
	 */
	static const uint8_t version_buffer[8] = {
		NTLMSSP_WINDOWS_MAJOR_VERSION_6,
		NTLMSSP_WINDOWS_MINOR_VERSION_1,
		0x00, 0x00, /* product build */
		0x00, 0x00, 0x00, /* reserved */
		NTLMSSP_REVISION_W2K3
	};

	return data_blob_const(version_buffer, ARRAY_SIZE(version_buffer));
}
