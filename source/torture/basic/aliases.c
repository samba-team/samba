/* 
   Unix SMB/CIFS implementation.
   SMB trans2 alias scanner
   Copyright (C) Andrew Tridgell 2003
   
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

#include "includes.h"
#include "dlinklist.h"

int create_complex_file(struct smbcli_state *cli, TALLOC_CTX *mem_ctx, const char *fname);

struct trans2_blobs {
	struct trans2_blobs *next, *prev;
	uint16_t level;
	DATA_BLOB params, data;
};

/* look for aliases for a query */
static void gen_aliases(struct smbcli_state *cli, struct smb_trans2 *t2, int level_offset)
{
	TALLOC_CTX *mem_ctx;
	uint16_t level;
	struct trans2_blobs *alias_blobs = NULL;
	struct trans2_blobs *t2b, *t2b2;
	int count=0, alias_count=0;

	mem_ctx = talloc_init("aliases");

	for (level=0;level<2000;level++) {
		NTSTATUS status;

		SSVAL(t2->in.params.data, level_offset, level);
		
		status = smb_raw_trans2(cli->tree, mem_ctx, t2);
		if (!NT_STATUS_IS_OK(status)) continue;

		t2b = talloc_p(mem_ctx, struct trans2_blobs);
		t2b->level = level;
		t2b->params = t2->out.params;
		t2b->data = t2->out.data;
		DLIST_ADD(alias_blobs, t2b);
		d_printf("\tFound level %4u (0x%03x) of size %3d (0x%02x)\n", 
			 level, level,
			 t2b->data.length, t2b->data.length);
		count++;
	}

	d_printf("Found %d levels with success status\n", count);

	for (t2b=alias_blobs; t2b; t2b=t2b->next) {
		for (t2b2=alias_blobs; t2b2; t2b2=t2b2->next) {
			if (t2b->level >= t2b2->level) continue;
			if (data_blob_equal(&t2b->params, &t2b2->params) &&
			    data_blob_equal(&t2b->data, &t2b2->data)) {
				printf("\tLevel %u (0x%x) and level %u (0x%x) are possible aliases\n", 
				       t2b->level, t2b->level, t2b2->level, t2b2->level);
				alias_count++;
			}
		}
	}

	d_printf("Found %d aliased levels\n", alias_count);
	
	talloc_destroy(mem_ctx);
}

/* look for qfsinfo aliases */
static void qfsinfo_aliases(struct smbcli_state *cli)
{
	struct smb_trans2 t2;
	uint16_t setup = TRANSACT2_QFSINFO;

	d_printf("\nChecking for QFSINFO aliases\n");

	t2.in.max_param = 0;
	t2.in.max_data = smb_raw_max_trans_data(cli->tree, 0);
	t2.in.max_setup = 0;
	t2.in.flags = 0;
	t2.in.timeout = 0;
	t2.in.setup_count = 1;
	t2.in.setup = &setup;
	t2.in.params = data_blob(NULL, 2);
	t2.in.data = data_blob(NULL, 0);

	gen_aliases(cli, &t2, 0);
}

/* look for qfileinfo aliases */
static void qfileinfo_aliases(struct smbcli_state *cli)
{
	struct smb_trans2 t2;
	uint16_t setup = TRANSACT2_QFILEINFO;
	const char *fname = "\\qfileinfo_aliases.txt";
	int fnum;

	d_printf("\nChecking for QFILEINFO aliases\n");

	t2.in.max_param = 2;
	t2.in.max_data = smb_raw_max_trans_data(cli->tree, 2);
	t2.in.max_setup = 0;
	t2.in.flags = 0;
	t2.in.timeout = 0;
	t2.in.setup_count = 1;
	t2.in.setup = &setup;
	t2.in.params = data_blob(NULL, 4);
	t2.in.data = data_blob(NULL, 0);

	smbcli_unlink(cli->tree, fname);
	fnum = create_complex_file(cli, cli, fname);
	if (fnum == -1) {
		printf("ERROR: open of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
	}

	smbcli_write(cli->tree, fnum, 0, &t2, 0, sizeof(t2));

	SSVAL(t2.in.params.data, 0, fnum);

	gen_aliases(cli, &t2, 2);

	smbcli_close(cli->tree, fnum);
	smbcli_unlink(cli->tree, fname);
}


/* look for qpathinfo aliases */
static void qpathinfo_aliases(struct smbcli_state *cli)
{
	struct smb_trans2 t2;
	uint16_t setup = TRANSACT2_QPATHINFO;
	const char *fname = "\\qpathinfo_aliases.txt";
	int fnum;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("qpathinfo");

	d_printf("\nChecking for QPATHINFO aliases\n");

	t2.in.max_param = 2;
	t2.in.max_data = smb_raw_max_trans_data(cli->tree, 2);
	t2.in.max_setup = 0;
	t2.in.flags = 0;
	t2.in.timeout = 0;
	t2.in.setup_count = 1;
	t2.in.setup = &setup;
	t2.in.params = data_blob_talloc(mem_ctx, NULL, 6);
	t2.in.data = data_blob(NULL, 0);

	smbcli_unlink(cli->tree, fname);
	fnum = create_complex_file(cli, cli, fname);
	if (fnum == -1) {
		printf("ERROR: open of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
	}

	smbcli_write(cli->tree, fnum, 0, &t2, 0, sizeof(t2));
	smbcli_close(cli->tree, fnum);

	SIVAL(t2.in.params.data, 2, 0);

	smbcli_blob_append_string(cli->session, mem_ctx, &t2.in.params, 
			       fname, STR_TERMINATE);

	gen_aliases(cli, &t2, 0);

	smbcli_unlink(cli->tree, fname);
	talloc_destroy(mem_ctx);
}


/* look for trans2 findfirst aliases */
static void findfirst_aliases(struct smbcli_state *cli)
{
	struct smb_trans2 t2;
	uint16_t setup = TRANSACT2_FINDFIRST;
	const char *fname = "\\findfirst_aliases.txt";
	int fnum;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("findfirst");

	d_printf("\nChecking for FINDFIRST aliases\n");

	t2.in.max_param = 16;
	t2.in.max_data = smb_raw_max_trans_data(cli->tree, 16);
	t2.in.max_setup = 0;
	t2.in.flags = 0;
	t2.in.timeout = 0;
	t2.in.setup_count = 1;
	t2.in.setup = &setup;
	t2.in.params = data_blob_talloc(mem_ctx, NULL, 12);
	t2.in.data = data_blob(NULL, 0);

	smbcli_unlink(cli->tree, fname);
	fnum = create_complex_file(cli, cli, fname);
	if (fnum == -1) {
		printf("ERROR: open of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
	}

	smbcli_write(cli->tree, fnum, 0, &t2, 0, sizeof(t2));
	smbcli_close(cli->tree, fnum);

	SSVAL(t2.in.params.data, 0, 0);
	SSVAL(t2.in.params.data, 2, 1);
	SSVAL(t2.in.params.data, 4, FLAG_TRANS2_FIND_CLOSE);
	SSVAL(t2.in.params.data, 6, 0);
	SIVAL(t2.in.params.data, 8, 0);

	smbcli_blob_append_string(cli->session, mem_ctx, &t2.in.params, 
			       fname, STR_TERMINATE);

	gen_aliases(cli, &t2, 6);

	smbcli_unlink(cli->tree, fname);
	talloc_destroy(mem_ctx);
}



/* look for aliases for a set function */
static void gen_set_aliases(struct smbcli_state *cli, struct smb_trans2 *t2, int level_offset)
{
	TALLOC_CTX *mem_ctx;
	uint16_t level;
	struct trans2_blobs *alias_blobs = NULL;
	struct trans2_blobs *t2b;
	int count=0, dsize;

	mem_ctx = talloc_init("aliases");

	for (level=1;level<1100;level++) {
		NTSTATUS status, status1;
		SSVAL(t2->in.params.data, level_offset, level);

		status1 = NT_STATUS_OK;

		for (dsize=2; dsize<1024; dsize += 2) {
			data_blob_free(&t2->in.data);
			t2->in.data = data_blob(NULL, dsize);
			data_blob_clear(&t2->in.data);
			status = smb_raw_trans2(cli->tree, mem_ctx, t2);
			/* some error codes mean that this whole level doesn't exist */
			if (NT_STATUS_EQUAL(NT_STATUS_INVALID_LEVEL, status) ||
			    NT_STATUS_EQUAL(NT_STATUS_INVALID_INFO_CLASS, status) ||
			    NT_STATUS_EQUAL(NT_STATUS_NOT_SUPPORTED, status)) {
				break;
			}
			if (NT_STATUS_IS_OK(status)) break;

			/* invalid parameter means that the level exists at this 
			   size, but the contents are wrong (not surprising with
			   all zeros!) */
			if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) break;

			/* this is the usual code for 'wrong size' */
			if (NT_STATUS_EQUAL(status, NT_STATUS_INFO_LENGTH_MISMATCH)) {
				continue;
			}

			if (!NT_STATUS_EQUAL(status, status1)) {
				printf("level=%d size=%d %s\n", level, dsize, nt_errstr(status));
			}
			status1 = status;
		}

		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) continue;

		t2b = talloc_p(mem_ctx, struct trans2_blobs);
		t2b->level = level;
		t2b->params = t2->out.params;
		t2b->data = t2->out.data;
		DLIST_ADD(alias_blobs, t2b);
		d_printf("\tFound level %4u (0x%03x) of size %3d (0x%02x)\n", 
			 level, level,
			 t2->in.data.length, t2->in.data.length);
		count++;
	}

	d_printf("Found %d valid levels\n", count);
	talloc_destroy(mem_ctx);
}



/* look for setfileinfo aliases */
static void setfileinfo_aliases(struct smbcli_state *cli)
{
	struct smb_trans2 t2;
	uint16_t setup = TRANSACT2_SETFILEINFO;
	const char *fname = "\\setfileinfo_aliases.txt";
	int fnum;

	d_printf("\nChecking for SETFILEINFO aliases\n");

	t2.in.max_param = 2;
	t2.in.max_data = 0;
	t2.in.max_setup = 0;
	t2.in.flags = 0;
	t2.in.timeout = 0;
	t2.in.setup_count = 1;
	t2.in.setup = &setup;
	t2.in.params = data_blob(NULL, 6);
	t2.in.data = data_blob(NULL, 0);

	smbcli_unlink(cli->tree, fname);
	fnum = create_complex_file(cli, cli, fname);
	if (fnum == -1) {
		printf("ERROR: open of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
	}

	smbcli_write(cli->tree, fnum, 0, &t2, 0, sizeof(t2));

	SSVAL(t2.in.params.data, 0, fnum);
	SSVAL(t2.in.params.data, 4, 0);

	gen_set_aliases(cli, &t2, 2);

	smbcli_close(cli->tree, fnum);
	smbcli_unlink(cli->tree, fname);
}

/* look for setpathinfo aliases */
static void setpathinfo_aliases(struct smbcli_state *cli)
{
	struct smb_trans2 t2;
	uint16_t setup = TRANSACT2_SETPATHINFO;
	const char *fname = "\\setpathinfo_aliases.txt";
	int fnum;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("findfirst");

	d_printf("\nChecking for SETPATHINFO aliases\n");

	t2.in.max_param = 32;
	t2.in.max_data = smb_raw_max_trans_data(cli->tree, 32);
	t2.in.max_setup = 0;
	t2.in.flags = 0;
	t2.in.timeout = 0;
	t2.in.setup_count = 1;
	t2.in.setup = &setup;
	t2.in.params = data_blob_talloc(mem_ctx, NULL, 4);
	t2.in.data = data_blob(NULL, 0);

	smbcli_unlink(cli->tree, fname);

	fnum = create_complex_file(cli, cli, fname);
	if (fnum == -1) {
		printf("ERROR: open of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
	}

	smbcli_write(cli->tree, fnum, 0, &t2, 0, sizeof(t2));
	smbcli_close(cli->tree, fnum);

	SSVAL(t2.in.params.data, 2, 0);

	smbcli_blob_append_string(cli->session, mem_ctx, &t2.in.params, 
			       fname, STR_TERMINATE);

	gen_set_aliases(cli, &t2, 0);

	if (NT_STATUS_IS_ERR(smbcli_unlink(cli->tree, fname))) {
		printf("unlink: %s\n", smbcli_errstr(cli->tree));
	}
	talloc_destroy(mem_ctx);
}


/* look for aliased info levels in trans2 calls */
BOOL torture_trans2_aliases(void)
{
	struct smbcli_state *cli;

	if (!torture_open_connection(&cli)) {
		return False;
	}


	qfsinfo_aliases(cli);
	qfileinfo_aliases(cli);
	qpathinfo_aliases(cli);
	findfirst_aliases(cli);
	setfileinfo_aliases(cli);
	setpathinfo_aliases(cli);

	if (!torture_close_connection(cli)) {
		return False;
	}

	return True;
}
