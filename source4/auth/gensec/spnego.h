/* 
   Unix SMB/CIFS implementation.

   RFC2478 Compliant SPNEGO implementation

   Copyright (C) Jim McDonough <jmcd@us.ibm.com>   2003

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

#define SPNEGO_DELEG_FLAG    0x01
#define SPNEGO_MUTUAL_FLAG   0x02
#define SPNEGO_REPLAY_FLAG   0x04
#define SPNEGO_SEQUENCE_FLAG 0x08
#define SPNEGO_ANON_FLAG     0x10
#define SPNEGO_CONF_FLAG     0x20
#define SPNEGO_INTEG_FLAG    0x40
#define SPNEGO_REQ_FLAG      0x80

enum spnego_negResult {
	SPNEGO_ACCEPT_COMPLETED = 0,
	SPNEGO_ACCEPT_INCOMPLETE = 1,
	SPNEGO_REJECT = 2,
	SPNEGO_NONE_RESULT = 3
};

struct spnego_negTokenInit {
	const char **mechTypes;
	int reqFlags;
	DATA_BLOB mechToken;
	DATA_BLOB mechListMIC;
	char *targetPrincipal;
};

struct spnego_negTokenTarg {
	uint8_t negResult;
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

#include "auth/gensec/spnego_proto.h"
