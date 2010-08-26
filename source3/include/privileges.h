
/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   Copyright (C) Simo Sorce 2003
   Copyright (C) Gerald (Jerry) Carter 2005
   Copyright (C) Andrew Bartlett 2010
   
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

#ifndef PRIVILEGES_H
#define PRIVILEGES_H

#include "../librpc/gen_ndr/lsa.h"
#include "../librpc/gen_ndr/security.h"

/* privilege bitmask */

/* common privilege defines */

#define SE_END				0x0
#define SE_NONE				0x0
#define SE_ALL_PRIVS                    (uint64_t)-1


/* defined in lib/privilegs_basic.c */

extern const uint64_t se_priv_all;

extern const uint64_t se_priv_none;
extern const uint64_t se_machine_account;
extern const uint64_t se_print_operator;
extern const uint64_t se_add_users;
extern const uint64_t se_disk_operators;
extern const uint64_t se_remote_shutdown;
extern const uint64_t se_restore;
extern const uint64_t se_take_ownership;


/*
 * These are used in Lsa replies (srv_lsa_nt.c)
 */

typedef struct {
	TALLOC_CTX *mem_ctx;
	bool ext_ctx;
	uint32 count;
	uint32 control;
	struct lsa_LUIDAttribute *set;
} PRIVILEGE_SET;

typedef struct {
	uint64_t se_priv;
	const char *name;
	const char *description;
	struct lsa_LUID luid;
} PRIVS;

#endif /* PRIVILEGES_H */
