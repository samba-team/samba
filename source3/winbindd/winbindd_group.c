/* 
   Unix SMB/CIFS implementation.

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000
   Copyright (C) Jeremy Allison 2001.
   Copyright (C) Gerald (Jerry) Carter 2003.
   Copyright (C) Volker Lendecke 2005
   
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

#include "includes.h"
#include "winbindd.h"
#include "lib/dbwrap/dbwrap.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

/* Fill a grent structure from various other information */

bool fill_grent(TALLOC_CTX *mem_ctx, struct winbindd_gr *gr,
		const char *dom_name, const char *gr_name, gid_t unix_gid)
{
	const char *full_group_name;
	char *mapped_name = NULL;
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;

	nt_status = normalize_name_map(mem_ctx, dom_name, gr_name,
				       &mapped_name);

	/* Basic whitespace replacement */
	if (NT_STATUS_IS_OK(nt_status)) {
		full_group_name = fill_domain_username_talloc(mem_ctx, dom_name,
				     mapped_name, true);
	}
	/* Mapped to an aliase */
	else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_FILE_RENAMED)) {
		full_group_name = mapped_name;
	}
	/* no change */
	else {
		full_group_name = fill_domain_username_talloc(mem_ctx, dom_name,
				      gr_name, True );
	}

	if (full_group_name == NULL) {
		return false;
	}

	gr->gr_gid = unix_gid;

	/* Group name and password */

	strlcpy(gr->gr_name, full_group_name, sizeof(gr->gr_name));
	strlcpy(gr->gr_passwd, "x", sizeof(gr->gr_passwd));

	return True;
}

struct getgr_countmem {
	int num;
	size_t len;
};

static int getgr_calc_memberlen(struct db_record *rec, void *private_data)
{
	struct getgr_countmem *buf = private_data;
	TDB_DATA data = dbwrap_record_get_value(rec);
	size_t len;

	buf->num += 1;

	len = buf->len + data.dsize;
	if (len < buf->len) {
		return 0;
	}
	buf->len = len;
	return 0;
}

struct getgr_stringmem {
	size_t ofs;
	char *buf;
};

static int getgr_unparse_members(struct db_record *rec, void *private_data)
{
	struct getgr_stringmem *buf = private_data;
	TDB_DATA data = dbwrap_record_get_value(rec);
	int len;

	len = data.dsize-1;

	memcpy(buf->buf + buf->ofs, data.dptr, len);
	buf->ofs += len;
	buf->buf[buf->ofs] = ',';
	buf->ofs += 1;
	return 0;
}

NTSTATUS winbindd_print_groupmembers(struct db_context *members,
				     TALLOC_CTX *mem_ctx,
				     int *num_members, char **result)
{
	struct getgr_countmem c;
	struct getgr_stringmem m;
	int count;
	NTSTATUS status;

	c.num = 0;
	c.len = 0;

	status = dbwrap_traverse(members, getgr_calc_memberlen, &c, &count);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("dbwrap_traverse failed: %s\n", nt_errstr(status));
		return status;
	}

	m.ofs = 0;
	m.buf = talloc_array(mem_ctx, char, c.len);
	if (m.buf == NULL) {
		DEBUG(5, ("talloc failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	status = dbwrap_traverse(members, getgr_unparse_members, &m, &count);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(m.buf);
		DBG_NOTICE("dbwrap_traverse failed: %s\n", nt_errstr(status));
		return status;
	}
	m.buf[c.len-1] = '\0';

	*num_members = c.num;
	*result = m.buf;
	return NT_STATUS_OK;
}
