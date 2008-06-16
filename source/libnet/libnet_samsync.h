/*
 *  Unix SMB/CIFS implementation.
 *  libnet Support
 *  Copyright (C) Guenther Deschner 2008
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


enum net_samsync_mode {
	NET_SAMSYNC_MODE_FETCH_PASSDB = 0,
	NET_SAMSYNC_MODE_FETCH_LDIF = 1,
	NET_SAMSYNC_MODE_DUMP = 2
};

/* Structure for mapping accounts to groups */
/* Array element is the group rid */
typedef struct _groupmap {
	uint32_t rid;
	uint32_t gidNumber;
	const char *sambaSID;
	const char *group_dn;
} GROUPMAP;

typedef struct _accountmap {
	uint32_t rid;
	const char *cn;
} ACCOUNTMAP;

struct samsync_ldif_context {
	GROUPMAP *groupmap;
	ACCOUNTMAP *accountmap;
	bool initialized;
	const char *add_template;
	const char *mod_template;
	char *add_name;
	char *mod_name;
	FILE *add_file;
	FILE *mod_file;
	FILE *ldif_file;
	const char *suffix;
	int num_alloced;
};

struct samsync_context {
	enum net_samsync_mode mode;
	const struct dom_sid *domain_sid;
	const char *domain_sid_str;
	const char *ldif_filename;
	struct samsync_ldif_context *ldif;
};

typedef NTSTATUS (*samsync_fn_t)(TALLOC_CTX *,
				 enum netr_SamDatabaseID,
				 struct netr_DELTA_ENUM_ARRAY *,
				 NTSTATUS,
				 struct samsync_context *);
