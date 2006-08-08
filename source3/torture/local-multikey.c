/* 
   Unix SMB/CIFS implementation.
   Run some local tests on the local tdb multikey wrapper
   Copyright (C) Volker Lendecke 2006
   
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

static char **key_fn(TALLOC_CTX *mem_ctx, TDB_DATA data,
		     void *private_data)
{
	fstring key, value;
	char **result;

	result = TALLOC_ARRAY(mem_ctx, char *, 3);
	if (result == NULL) {
		return NULL;
	}

	if (tdb_unpack(data.dptr, data.dsize, "ff", key, value) < 0) {
		d_fprintf(stderr, "tdb_unpack failed\n");
		TALLOC_FREE(result);
		return NULL;
	}
	result[0] = talloc_strdup(result, key);
	result[1] = talloc_strdup(result, value);
	result[2] = NULL;

	if ((result[0] == NULL) || (result[1] == NULL)) {
		d_fprintf(stderr, "talloc_strdup failed\n");
		TALLOC_FREE(result);
		return NULL;
	}

	return result;
}

static NTSTATUS multikey_add(struct tdb_context *tdb, const char *key,
			     const char *value)
{
	NTSTATUS status;
	TDB_DATA data;

	data.dptr = NULL;
	data.dsize = 0;

	if (!tdb_pack_append(NULL, &data.dptr, &data.dsize,
			     "ff", key, value)) {
		return NT_STATUS_NO_MEMORY;
	}

	status = tdb_add_keyed(tdb, key_fn, data, NULL);
	TALLOC_FREE(data.dptr);
	return status;
}

#define CHECK_STATUS(_status, _expected) do { \
	if (!NT_STATUS_EQUAL(_status, _expected)) { \
		printf("(%d) Incorrect status %s - should be %s\n", \
		       __LINE__, nt_errstr(status), nt_errstr(_expected)); \
		ret = False; \
		goto fail; \
	}} while (0)

#define NUM_ELEMENTS (50)

BOOL run_local_multikey(int dummy)
{
	TALLOC_CTX *mem_ctx;
	char *prim;
	const char *tdbname = "multi_key_test.tdb";
	struct tdb_context *tdb = NULL;
	NTSTATUS status;
	BOOL ret = False;
	TDB_DATA data;
	int i;
	fstring key,value;

	unlink(tdbname);

	mem_ctx = talloc_init("run_local_multikey");
	if (mem_ctx == NULL) {
		d_fprintf(stderr, "talloc_init failed\n");
		return False;
	}

	tdb = tdb_open(tdbname, 0, 0, O_CREAT|O_RDWR, 0644);
	if (tdb == NULL) {
		d_fprintf(stderr, "tdb_open failed: %s\n", strerror(errno));
		goto fail;
	}

	for (i=0; i<NUM_ELEMENTS; i++) {
		fstr_sprintf(key, "KEY%d", i);
		fstr_sprintf(value, "VAL%d", i);

		status = multikey_add(tdb, key, value);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr, "tdb_add_keyed failed: %s\n",
				  nt_errstr(status));
			goto fail;
		}
	}

	{
		struct tdb_keyed_iterator *it = tdb_enum_keyed(mem_ctx, tdb);
		if (it == NULL) {
			d_printf("tdb_enum_keyed failed\n");
			goto fail;
		}

		i = 0;

		while (tdb_next_keyed(it, &data)) {
			i += 1;
			if (i > 1000) {
				d_printf("tdb_next_keyed overrun\n");
				goto fail;
			}
		}

		if (i != NUM_ELEMENTS) {
			d_printf("counted %d, elements, expected %d\n",
				 i, NUM_ELEMENTS);
			goto fail;
		}
	}

	status = multikey_add(tdb, "KEY35", "FOOO");
	CHECK_STATUS(status, NT_STATUS_OBJECTID_EXISTS);
	status = multikey_add(tdb, "KEY42", "VAL45");
	CHECK_STATUS(status, NT_STATUS_OBJECTID_EXISTS);
	status = multikey_add(tdb, "FOO", "VAL45");
	CHECK_STATUS(status, NT_STATUS_OBJECTID_EXISTS);

	for (i=0; i<NUM_ELEMENTS; i++) {
		fstr_sprintf(key, "KEY%d", i);
		fstr_sprintf(value, "VAL%d", i);

		status = tdb_find_keyed(mem_ctx, tdb, 0, key, &data, &prim);
		CHECK_STATUS(status, NT_STATUS_OK);
		status = tdb_find_keyed(mem_ctx, tdb, 1, value, &data, &prim);
		CHECK_STATUS(status, NT_STATUS_OK);
		status = tdb_find_keyed(mem_ctx, tdb, 1, key, &data, &prim);
		CHECK_STATUS(status, NT_STATUS_NOT_FOUND);
		status = tdb_find_keyed(mem_ctx, tdb, 0, value, &data, &prim);
		CHECK_STATUS(status, NT_STATUS_NOT_FOUND);
	}

	status = tdb_find_keyed(mem_ctx, tdb, 0, "FOO", &data, &prim);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);
	status = tdb_find_keyed(mem_ctx, tdb, 1, "BAR", &data, &prim);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);

	status = tdb_find_keyed(mem_ctx, tdb, 0, "KEY0", &data, &prim);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(data);
	if (tdb_pack_append(mem_ctx, &data.dptr, &data.dsize, "ff",
			    "NEWKEY", "NEWVAL") < 0) {
		d_printf("tdb_pack_alloc failed\n");
		goto fail;
	}

	status = tdb_update_keyed(tdb, prim, key_fn, data, NULL);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = tdb_find_keyed(mem_ctx, tdb, 0, "KEY0", &data, &prim);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);
	status = tdb_find_keyed(mem_ctx, tdb, 1, "VAL0", &data, &prim);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);
	status = tdb_find_keyed(mem_ctx, tdb, 0, "NEWKEY", &data, &prim);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = tdb_find_keyed(mem_ctx, tdb, 1, "NEWVAL", &data, &prim);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = tdb_del_keyed(tdb, key_fn, prim, NULL);
	CHECK_STATUS(status, NT_STATUS_OK);

	for (i=1; i<NUM_ELEMENTS; i++) {
		fstr_sprintf(key, "KEY%d", i);
		status = tdb_find_keyed(mem_ctx, tdb, 0, key, &data, &prim);
		CHECK_STATUS(status, NT_STATUS_OK);
		status = tdb_del_keyed(tdb, key_fn, prim, NULL);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

	ret = True;
 fail:
	if (tdb != NULL) {
		tdb_close(tdb);
	}
	unlink(tdbname);
	TALLOC_FREE(mem_ctx);
	return ret;
}

