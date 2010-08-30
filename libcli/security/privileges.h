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
	uint32_t count;
	uint32_t control;
	struct lsa_LUIDAttribute *set;
} PRIVILEGE_SET;

/*
  return a privilege mask given a privilege id
*/
uint64_t sec_privilege_mask(enum sec_privilege privilege);

/***************************************************************************
 copy an uint64_t structure
****************************************************************************/

bool se_priv_copy( uint64_t *dst, const uint64_t *src );

/***************************************************************************
 put all privileges into a mask
****************************************************************************/

bool se_priv_put_all_privileges(uint64_t *privilege_mask);

/*********************************************************************
 Lookup the uint64_t value for a privilege name
*********************************************************************/

bool se_priv_from_name( const char *name, uint64_t *privilege_mask );

/****************************************************************************
 check if the privilege is in the privilege list
****************************************************************************/

bool is_privilege_assigned(const uint64_t *privileges,
			   const uint64_t *check);

const char* get_privilege_dispname( const char *name );

/****************************************************************************
 Does the user have the specified privilege ?  We only deal with one privilege
 at a time here.
*****************************************************************************/

bool user_has_privileges(const struct security_token *token, const uint64_t *privilege_bit);

/****************************************************************************
 Does the user have any of the specified privileges ?  We only deal with one privilege
 at a time here.
*****************************************************************************/

bool user_has_any_privilege(struct security_token *token, const uint64_t *privilege_mask);

/*******************************************************************
 return the number of elements in the 'short' privlege array (traditional source3 behaviour)
*******************************************************************/

int num_privileges_in_short_list( void );

/****************************************************************************
 Convert a LUID to a named string
****************************************************************************/

bool se_priv_to_privilege_set( PRIVILEGE_SET *set, uint64_t privilege_mask );
bool privilege_set_to_se_priv( uint64_t *privilege_mask, struct lsa_PrivilegeSet *privset );

/*
  map a privilege id to the wire string constant
*/
const char *sec_privilege_name(enum sec_privilege privilege);

/*
  map a privilege id to a privilege display name. Return NULL if not found

  TODO: this should use language mappings
*/
const char *sec_privilege_display_name(enum sec_privilege privilege, uint16_t *language);

/*
  map a privilege name to a privilege id. Return -1 if not found
*/
enum sec_privilege sec_privilege_id(const char *name);

/*
  map a privilege name to a privilege id. Return -1 if not found
*/
enum sec_privilege sec_privilege_from_mask(uint64_t mask);

/*
  assist in walking the table of privileges - return the LUID (low 32 bits) by index
*/
enum sec_privilege sec_privilege_from_index(int idx);

/*
  assist in walking the table of privileges - return the string constant by index
*/
const char *sec_privilege_name_from_index(int idx);

/*
  return true if a security_token has a particular privilege bit set
*/
bool security_token_has_privilege(const struct security_token *token, enum sec_privilege privilege);

/*
  set a bit in the privilege mask
*/
void security_token_set_privilege(struct security_token *token, enum sec_privilege privilege);

void security_token_debug_privileges(int dbg_lev, const struct security_token *token);

#endif /* PRIVILEGES_H */
