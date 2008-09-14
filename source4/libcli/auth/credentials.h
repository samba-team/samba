/* 
   Unix SMB/CIFS implementation.

   code to manipulate domain credentials

   Copyright (C) Andrew Tridgell 2004
   
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

#include "librpc/gen_ndr/netlogon.h"

struct creds_CredentialState {
	uint32_t negotiate_flags;
	uint8_t session_key[16];
	uint32_t sequence;
	struct netr_Credential seed;
	struct netr_Credential client;
	struct netr_Credential server;
	uint16_t secure_channel_type;
	const char *domain;
	const char *computer_name;
	const char *account_name;
	struct dom_sid *sid;
};

/* for the timebeing, use the same neg flags as Samba3. */
/* The 7 here seems to be required to get Win2k not to downgrade us
   to NT4.  Actually, anything other than 1ff would seem to do... */
#define NETLOGON_NEG_AUTH2_FLAGS     0x000701ff

/* these are the flags that ADS clients use */
#define NETLOGON_NEG_AUTH2_ADS_FLAGS (0x200fbffb | NETLOGON_NEG_ARCFOUR | NETLOGON_NEG_128BIT | NETLOGON_NEG_SCHANNEL)


