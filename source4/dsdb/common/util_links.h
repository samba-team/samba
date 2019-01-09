/*
   Unix SMB/CIFS implementation.

   Helpers to search for links in the DB

   Copyright (C) Catalyst.Net Ltd 2017

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

#ifndef __DSDB_COMMON_UTIL_LINKS_H__
#define __DSDB_COMMON_UTIL_LINKS_H__

struct compare_ctx {
        const struct GUID *guid;
        struct ldb_context *ldb;
        TALLOC_CTX *mem_ctx;
        const char *ldap_oid;
        int err;
        const struct GUID *invocation_id;
        DATA_BLOB extra_part;
        size_t partial_extra_part_length;
        bool compare_extra_part;
};

struct parsed_dn {
	struct dsdb_dn *dsdb_dn;
	struct GUID guid;
	struct ldb_val *v;
};


int get_parsed_dns_trusted(TALLOC_CTX *mem_ctx,
			   struct ldb_message_element *el,
			   struct parsed_dn **pdn);

#endif /* __DSDB_COMMON_UTIL_LINKS_H__ */
