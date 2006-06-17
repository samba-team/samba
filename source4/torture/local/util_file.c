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

static BOOL test_file_load_save(struct torture_context *test, const void *_data)
{
	size_t len;
	char *data;
	
	torture_assert(test, 
				   file_save(TEST_FILENAME, TEST_DATA, strlen(TEST_DATA)),
				   "saving file");

	data = file_load(TEST_FILENAME, &len, test);
	torture_assert(test, data, "loading file");

	torture_assert(test, len == strlen(TEST_DATA), "Length");
	
	torture_assert(test, memcmp(data, TEST_DATA, len) == 0, "Contents");

	unlink(TEST_FILENAME);

	return True;
}

static BOOL test_afdgets(struct torture_context *test, const void *data)
{
	int fd;
	char *line;
	
	torture_assert(test, 
				   file_save(TEST_FILENAME, (const void *)TEST_DATA, 
							 strlen(TEST_DATA)),
				   "saving file");

	fd = open(TEST_FILENAME, O_RDONLY);
	
	torture_assert(test, fd != -1, "opening file");

	line = afdgets(fd, test, 8);
	torture_assert(test, strcmp(line, TEST_LINE1) == 0, "line 1 mismatch");

	line = afdgets(fd, test, 8);
	torture_assert(test, strcmp(line, TEST_LINE2) == 0, "line 2 mismatch");

	line = afdgets(fd, test, 8);
	torture_assert(test, strcmp(line, TEST_LINE3) == 0, "line 3 mismatch");

	close(fd);

	unlink(TEST_FILENAME);

	return True;
}

struct torture_suite *torture_local_util_file(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "LOCAL-FILE");

	torture_suite_add_simple_tcase(suite, "file_load_save", 
								   test_file_load_save, NULL);

	torture_suite_add_simple_tcase(suite, "afdgets", 
								   test_afdgets, NULL);

	return suite;
}
