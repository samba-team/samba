/* 
   Unix SMB/CIFS implementation.

   RFC2478 Compliant SPNEGO implementation

   Copyright (C) Jim McDonough <jmcd@us.ibm.com>   2003

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef SAMBA_SPNEGO_H
#define SAMBA_SPNEGO_H
/* SPNEGO mode */
enum spnego_role
{
	SPNEGO_SERVER,
	SPNEGO_CLIENT
};

#define SPNEGO_DELEG_FLAG    0x01
#define SPNEGO_MUTUAL_FLAG   0x02
#define SPNEGO_REPLAY_FLAG   0x04
#define SPNEGO_SEQUENCE_FLAG 0x08
#define SPNEGO_ANON_FLAG     0x10
#define SPNEGO_CONF_FLAG     0x20
#define SPNEGO_INTEG_FLAG    0x40
#define SPNEGO_REQ_FLAG      0x80

typedef enum _spnego_negResult {
	SPNEGO_ACCEPT_COMPLETED = 0,
	SPNEGO_ACCEPT_INCOMPLETE = 1,
	SPNEGO_REJECT = 2
} negResult_t;

struct spnego_negTokenInit {
	char **mechTypes;
	int reqFlags;
	DATA_BLOB mechToken;
	DATA_BLOB mechListMIC;
};

struct spnego_negTokenTarg {
	uint8 negResult;
	const char *supportedMech;
	DATA_BLOB responseToken;
	DATA_BLOB mechListMIC;
};

struct spnego_data {
	int type;
	struct spnego_negTokenInit negTokenInit;
	struct spnego_negTokenTarg negTokenTarg;
};

enum spnego_message_type {
	SPNEGO_NEG_TOKEN_INIT = 0, 
	SPNEGO_NEG_TOKEN_TARG = 1,
};

enum spnego_state_position {
	SPNEGO_SERVER_START,
	SPNEGO_CLIENT_GET_MECHS,
	SPNEGO_CLIENT_SEND_MECHS,
	SPNEGO_TARG,
	SPNEGO_FALLBACK,
	SPNEGO_DONE
};

struct spnego_state {
	TALLOC_CTX *mem_ctx;
	uint_t ref_count;
	enum spnego_role role;
	enum spnego_message_type expected_packet;
	enum spnego_message_type state_position;
	negResult_t result;
	struct gensec_security sub_sec_security;
};

#endif
