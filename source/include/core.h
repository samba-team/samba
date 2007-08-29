/* 
   Unix SMB/CIFS implementation.
   Core Samba data types

   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Stefan Metzmacher			  2004
   Copyright (C) Jelmer Vernooij			  2005
   
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

#ifndef _SAMBA_CORE_H
#define _SAMBA_CORE_H

#include "libcli/util/nt_status.h"

#include <stdlib.h>

/* by making struct ldb_val and DATA_BLOB the same, we can simplify
   a fair bit of code */
#define ldb_val datablob

/*
  we use struct ipv4_addr to avoid having to include all the
  system networking headers everywhere
*/
struct ipv4_addr {
	uint32_t addr;
};

typedef NTSTATUS (*init_module_fn) (void);

/* 
   use the same structure for dom_sid2 as dom_sid. A dom_sid2 is really
   just a dom sid, but with the sub_auths represented as a conformant
   array. As with all in-structure conformant arrays, the array length
   is placed before the start of the structure. That's what gives rise
   to the extra num_auths elemenent. We don't want the Samba code to
   have to bother with such esoteric NDR details, so its easier to just
   define it as a dom_sid and use pidl magic to make it all work. It
   just means you need to mark a sid as a "dom_sid2" in the IDL when you
   know it is of the conformant array variety
*/
#define dom_sid2 dom_sid

/* same struct as dom_sid but inside a 28 bytes fixed buffer in NDR */
#define dom_sid28 dom_sid

/* protocol types. It assumes that higher protocols include lower protocols
   as subsets. FIXME: Move to one of the smb-specific headers */
enum protocol_types {
	PROTOCOL_NONE,
	PROTOCOL_CORE,
	PROTOCOL_COREPLUS,
	PROTOCOL_LANMAN1,
	PROTOCOL_LANMAN2,
	PROTOCOL_NT1,
	PROTOCOL_SMB2
};

/* passed to br lock code. FIXME: Move to one of the smb-specific headers */
enum brl_type {
	READ_LOCK,
	WRITE_LOCK,
	PENDING_READ_LOCK,
	PENDING_WRITE_LOCK
};

enum server_role {
	ROLE_STANDALONE=0,
	ROLE_DOMAIN_MEMBER=1,
	ROLE_DOMAIN_CONTROLLER=2,
};

enum announce_as {/* Types of machine we can announce as. */
	ANNOUNCE_AS_NT_SERVER=1,
	ANNOUNCE_AS_WIN95=2,
	ANNOUNCE_AS_WFW=3,
	ANNOUNCE_AS_NT_WORKSTATION=4
};

#endif /* _SAMBA_CORE_H */
