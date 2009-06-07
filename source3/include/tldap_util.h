/*
   Unix SMB/CIFS implementation.
   Infrastructure for async ldap client requests
   Copyright (C) Volker Lendecke 2009

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

#ifndef __TLDAP_UTIL_H__
#define __TLDAP_UTIL_H__

#include "includes.h"

bool tldap_entry_values(struct tldap_message *msg, const char *attribute,
			int *num_values, DATA_BLOB **values);
bool tldap_get_single_valueblob(struct tldap_message *msg,
				const char *attribute, DATA_BLOB *blob);
char *tldap_talloc_single_attribute(struct tldap_message *msg,
				    const char *attribute,
				    TALLOC_CTX *mem_ctx);
bool tldap_pull_binsid(struct tldap_message *msg, const char *attribute,
		       struct dom_sid *sid);
bool tldap_add_mod_blobs(TALLOC_CTX *mem_ctx, struct tldap_mod **pmods,
			 int mod_op, const char *attrib,
			 int num_values, DATA_BLOB *values);
bool tldap_make_mod_blob(struct tldap_message *existing, TALLOC_CTX *mem_ctx,
			 int *pnum_mods, struct tldap_mod **pmods,
			 const char *attrib, DATA_BLOB newval);
bool tldap_make_mod_fmt(struct tldap_message *existing, TALLOC_CTX *mem_ctx,
			int *pnum_mods, struct tldap_mod **pmods,
			const char *attrib, const char *fmt, ...);

const char *tldap_errstr(TALLOC_CTX *mem_ctx, struct tldap_context *ld,
			 int rc);
int tldap_search_fmt(struct tldap_context *ld, const char *base, int scope,
		     const char *attrs[], int num_attrs, int attrsonly,
		     TALLOC_CTX *mem_ctx, struct tldap_message ***res,
		     const char *fmt, ...);
bool tldap_pull_uint64(struct tldap_message *msg, const char *attr,
		       uint64_t *presult);
bool tldap_pull_uint32(struct tldap_message *msg, const char *attr,
		       uint32_t *presult);

#endif
