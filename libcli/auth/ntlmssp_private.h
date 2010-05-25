/*
 *  Unix SMB/CIFS implementation.
 *  Version 3.0
 *  NTLMSSP Signing routines
 *  Copyright (C) Andrew Bartlett 2003-2005
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* For structures internal to the NTLMSSP implementation that should not be exposed */

#include "../lib/crypto/arcfour.h"

struct ntlmssp_crypt_direction {
	uint32_t seq_num;
	uint8_t sign_key[16];
	struct arcfour_state seal_state;
};

union ntlmssp_crypt_state {
	/* NTLM */
	struct ntlmssp_crypt_direction ntlm;

	/* NTLM2 */
	struct {
		struct ntlmssp_crypt_direction sending;
		struct ntlmssp_crypt_direction receiving;
	} ntlm2;
};

/* The following definitions come from libcli/auth/ntlmssp.c  */

void debug_ntlmssp_flags(uint32_t neg_flags);
