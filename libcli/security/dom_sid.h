/*
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Stefan (metze) Metzmacher 	2002-2004
   Copyright (C) Andrew Tridgell 		1992-2004
   Copyright (C) Jeremy Allison  		1999

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

#ifndef _DOM_SID_H_
#define _DOM_SID_H_

#include "replace.h"
#include <talloc.h>
#include "lib/util/data_blob.h"
#include "libcli/util/ntstatus.h"
#include "librpc/gen_ndr/security.h"

/* Some well-known SIDs */
extern const struct dom_sid global_sid_World_Domain;
extern const struct dom_sid global_sid_World;
extern const struct dom_sid global_sid_Local_Authority;
extern const struct dom_sid global_sid_Creator_Owner_Domain;
extern const struct dom_sid global_sid_NonUnique_Authority;
extern const struct dom_sid global_sid_NT_Authority;
extern const struct dom_sid global_sid_Enterprise_DCs;
extern const struct dom_sid global_sid_System;
extern const struct dom_sid global_sid_NULL;
extern const struct dom_sid global_sid_Self;
extern const struct dom_sid global_sid_Authenticated_Users;
extern const struct dom_sid global_sid_Network;
extern const struct dom_sid global_sid_NTLM_Authentication;
extern const struct dom_sid global_sid_Asserted_Identity;
extern const struct dom_sid global_sid_Asserted_Identity_Service;
extern const struct dom_sid global_sid_Asserted_Identity_Authentication_Authority;
extern const struct dom_sid global_sid_Fresh_Public_Key_Identity;
extern const struct dom_sid global_sid_Creator_Owner;
extern const struct dom_sid global_sid_Creator_Group;
extern const struct dom_sid global_sid_Owner_Rights;
extern const struct dom_sid global_sid_Anonymous;
extern const struct dom_sid global_sid_Compounded_Authentication;
extern const struct dom_sid global_sid_Claims_Valid;
extern const struct dom_sid global_sid_This_Organization;
extern const struct dom_sid global_sid_This_Organization_Certificate;
extern const struct dom_sid global_sid_Other_Organization;
extern const struct dom_sid global_sid_Passport_Authority;
extern const struct dom_sid global_sid_Mandatory_Label_Authority;
extern const struct dom_sid global_sid_Builtin_Package_Any_Package;
extern const struct dom_sid global_sid_Builtin;
extern const struct dom_sid global_sid_Builtin_Administrators;
extern const struct dom_sid global_sid_Builtin_Users;
extern const struct dom_sid global_sid_Builtin_Guests;
extern const struct dom_sid global_sid_Builtin_Power_Users;
extern const struct dom_sid global_sid_Builtin_Account_Operators;
extern const struct dom_sid global_sid_Builtin_Server_Operators;
extern const struct dom_sid global_sid_Builtin_Print_Operators;
extern const struct dom_sid global_sid_Builtin_Backup_Operators;
extern const struct dom_sid global_sid_Builtin_Replicator;
extern const struct dom_sid global_sid_Builtin_PreWin2kAccess;
extern const struct dom_sid global_sid_Unix_Users;
extern const struct dom_sid global_sid_Unix_Groups;
extern const struct dom_sid global_sid_Unix_NFS;
extern const struct dom_sid global_sid_Unix_NFS_Users;
extern const struct dom_sid global_sid_Unix_NFS_Groups;
extern const struct dom_sid global_sid_Unix_NFS_Mode;
extern const struct dom_sid global_sid_Unix_NFS_Other;
extern const struct dom_sid global_sid_Samba_SMB3;

extern const struct dom_sid global_sid_Samba_NPA_Flags;
#define SAMBA_NPA_FLAGS_NEED_IDLE 1
#define SAMBA_NPA_FLAGS_WINBIND_OFF 2

struct auth_SidAttr;
enum lsa_SidType;

NTSTATUS dom_sid_lookup_predefined_name(const char *name,
					const struct dom_sid **sid,
					enum lsa_SidType *type,
					const struct dom_sid **authority_sid,
					const char **authority_name);
NTSTATUS dom_sid_lookup_predefined_sid(const struct dom_sid *sid,
				       const char **name,
				       enum lsa_SidType *type,
				       const struct dom_sid **authority_sid,
				       const char **authority_name);
bool dom_sid_lookup_is_predefined_domain(const char *domain);

int dom_sid_compare_auth(const struct dom_sid *sid1,
			 const struct dom_sid *sid2);
int dom_sid_compare(const struct dom_sid *sid1, const struct dom_sid *sid2);
int dom_sid_compare_domain(const struct dom_sid *sid1,
			   const struct dom_sid *sid2);
bool dom_sid_equal(const struct dom_sid *sid1, const struct dom_sid *sid2);
bool sid_append_rid(struct dom_sid *sid, uint32_t rid);
bool string_to_sid(struct dom_sid *sidout, const char *sidstr);
bool dom_sid_parse_endp(const char *sidstr,struct dom_sid *sidout,
			const char **endp);
bool dom_sid_parse(const char *sidstr, struct dom_sid *ret);
struct dom_sid *dom_sid_parse_talloc(TALLOC_CTX *mem_ctx, const char *sidstr);
struct dom_sid *dom_sid_parse_length(TALLOC_CTX *mem_ctx, const DATA_BLOB *sid);
struct dom_sid *dom_sid_dup(TALLOC_CTX *mem_ctx, const struct dom_sid *dom_sid);
struct dom_sid *dom_sid_add_rid(TALLOC_CTX *mem_ctx,
				const struct dom_sid *domain_sid,
				uint32_t rid);
NTSTATUS dom_sid_split_rid(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
			   struct dom_sid **domain, uint32_t *rid);
bool dom_sid_match_prefix(const struct dom_sid *prefix_sid,
			  const struct dom_sid *sid);
bool dom_sid_in_domain(const struct dom_sid *domain_sid,
		       const struct dom_sid *sid);
bool dom_sid_has_account_domain(const struct dom_sid *sid);
bool dom_sid_is_valid_account_domain(const struct dom_sid *sid);

#define DOM_SID_STR_BUFLEN (15*11+25)
char *dom_sid_string(TALLOC_CTX *mem_ctx, const struct dom_sid *sid);

struct dom_sid_buf { char buf[DOM_SID_STR_BUFLEN]; };
char *dom_sid_str_buf(const struct dom_sid *sid, struct dom_sid_buf *dst);

const char *sid_type_lookup(uint32_t sid_type);
const struct security_token *get_system_token(void);
bool sid_compose(struct dom_sid *dst, const struct dom_sid *domain_sid, uint32_t rid);
bool sid_split_rid(struct dom_sid *sid, uint32_t *rid);
bool sid_peek_rid(const struct dom_sid *sid, uint32_t *rid);
bool sid_peek_check_rid(const struct dom_sid *exp_dom_sid, const struct dom_sid *sid, uint32_t *rid);
void sid_copy(struct dom_sid *dst, const struct dom_sid *src);
ssize_t sid_parse(const uint8_t *inbuf, size_t len, struct dom_sid *sid);
NTSTATUS add_sid_to_array(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
			  struct dom_sid **sids, uint32_t *num);
NTSTATUS add_sid_to_array_unique(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
				 struct dom_sid **sids, uint32_t *num_sids);
NTSTATUS add_sid_to_array_attrs(TALLOC_CTX *mem_ctx,
				const struct dom_sid *sid, uint32_t attrs,
				struct auth_SidAttr **sids, uint32_t *num);
NTSTATUS add_sid_to_array_attrs_unique(TALLOC_CTX *mem_ctx,
				       const struct dom_sid *sid, uint32_t attrs,
				       struct auth_SidAttr **sids, uint32_t *num_sids);
void del_sid_from_array(const struct dom_sid *sid, struct dom_sid **sids,
			uint32_t *num);
bool add_rid_to_array_unique(TALLOC_CTX *mem_ctx,
			     uint32_t rid, uint32_t **pp_rids, size_t *p_num);
bool is_null_sid(const struct dom_sid *sid);
bool sids_contains_sid(const struct dom_sid *sids,
		       const uint32_t num_sids,
		       const struct dom_sid *sid);
bool sid_attrs_contains_sid(const struct auth_SidAttr *sids,
			    const uint32_t num_sids,
			    const struct dom_sid *sid);
bool sids_contains_sid_attrs(const struct auth_SidAttr *sids,
			     const uint32_t num_sids,
			     const struct dom_sid *sid,
			     uint32_t attrs);

#endif /*_DOM_SID_H_*/
