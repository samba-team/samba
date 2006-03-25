/* 
   Unix SMB/CIFS implementation.

   util_file testing

   Copyright (C) Jelmer Vernooij 2005
   
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
#include "system/filesys.h"
#include "torture/torture.h"

#define TEST_FILENAME "utilfile.test"
#define TEST_LINE1 "This is list line 1..."
#define TEST_LINE2 ".. and this is line 2"
#define TEST_LINE3 "and end of the file"

#define TEST_DATA TEST_LINE1 "\n" TEST_LINE2 "\n" TEST_LINE3

static BOOL test_file_load_save(TALLOC_CTX *mem_ctx)
{
	BOOL ret;
	size_t len;
	char *data;
	
	ret = file_save(TEST_FILENAME, TEST_DATA, strlen(TEST_DATA));
	if (!ret)
		return False;

	data = file_load(TEST_FILENAME, &len, mem_ctx);
	if (!data) 
		return False;

	if (len != strlen(TEST_DATA))
		return False;
	
	if (memcmp(data, TEST_DATA, len) != 0)
		return False;

	unlink(TEST_FILENAME);

	return True;
}

static BOOL test_afdgets(TALLOC_CTX *mem_ctx)
{
	int fd;
	char *line;
	
	if (!file_save(TEST_FILENAME, (const void *)TEST_DATA, strlen(TEST_DATA)))
		return False;

	fd = open(TEST_FILENAME, O_RDONLY);
	
	if (fd == -1) 
		return False;

	line = afdgets(fd, mem_ctx, 8);
	if (strcmp(line, TEST_LINE1) != 0) 
		return False;

	line = afdgets(fd, mem_ctx, 8);
	if (strcmp(line, TEST_LINE2) != 0) 
		return False;

	line = afdgets(fd, mem_ctx, 8);
	if (strcmp(line, TEST_LINE3) != 0) 
		return False;

	close(fd);

	unlink(TEST_FILENAME);

	return True;
}

BOOL torture_local_util_file(struct torture_context *torture) 
{
	BOOL ret = True;
	TALLOC_CTX *mem_ctx = talloc_init("test_util_file");

	ret &= test_file_load_save(mem_ctx);
	ret &= test_afdgets(mem_ctx);

	talloc_free(mem_ctx);

	return ret;
}
