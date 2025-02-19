/* 
   Unix SMB/CIFS implementation.

   util_file testing

   Copyright (C) Jelmer Vernooij 2005
   
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
#include "lib/util/util_file.h"
#include "system/filesys.h"
#include "torture/torture.h"
#include "torture/local/proto.h"

#define TEST_FILENAME "utilfile.test"
#define TEST_LINE1 "This is list line 1..."
#define TEST_LINE2 ".. and this is line 2"
#define TEST_LINE3 "and end of the file"

#define TEST_DATA TEST_LINE1 "\n" TEST_LINE2 "\n" TEST_LINE3

static bool test_file_load_save(struct torture_context *tctx)
{
	size_t len;
	char *data;
	TALLOC_CTX *mem_ctx = tctx;
	
	torture_assert(tctx, file_save(TEST_FILENAME, TEST_DATA, strlen(TEST_DATA)),
				   "saving file");

	torture_assert_file_contains_text(tctx, TEST_FILENAME, TEST_DATA, 
								      "file contents");

	data = file_load(TEST_FILENAME, &len, 0, mem_ctx);
	torture_assert(tctx, data, "loading file");

	torture_assert_int_equal(tctx, len, strlen(TEST_DATA), "Length");
	
	torture_assert_mem_equal(tctx, data, TEST_DATA, len, "Contents");

	data = file_load(TEST_FILENAME, &len, 5, mem_ctx);

	torture_assert_int_equal(tctx, len, 5, "Length");

	torture_assert_mem_equal(tctx, data, TEST_DATA, len, "Contents");

	unlink(TEST_FILENAME);
	return true;
}

#define TEST_DATA_WITH_NEWLINE TEST_DATA "\n"
#define TEST_DATA_NO_NEWLINE TEST_DATA
#define TEST_DATA_EMPTY ""
#define TEST_DATA_BLANKS_ONLY "\n\n\n\n\n"
#define TEST_DATA_WITH_TRAILING_BLANKS TEST_DATA TEST_DATA_BLANKS_ONLY

static bool test_file_lines_load(struct torture_context *tctx)
{
	char **lines;
	int numlines;
	TALLOC_CTX *mem_ctx = tctx;

	/*
	 * Last line has trailing whitespace
	 */

	torture_assert(tctx,
		       file_save(TEST_FILENAME,
				 TEST_DATA_WITH_NEWLINE,
				 strlen(TEST_DATA_WITH_NEWLINE)),
		       "saving file");

	lines = file_lines_load(TEST_FILENAME, &numlines, 0, mem_ctx);

	torture_assert_int_equal(tctx, numlines, 3, "Lines");

	torture_assert_mem_equal(tctx,
				 lines[0],
				 TEST_LINE1,
				 strlen(TEST_LINE1),
				 "Line 1");

	torture_assert_mem_equal(tctx,
				 lines[1],
				 TEST_LINE2,
				 strlen(TEST_LINE2),
				 "Line 2");

	torture_assert_mem_equal(tctx,
				 lines[2],
				 TEST_LINE3,
				 strlen(TEST_LINE3),
				 "Line 3");

	unlink(TEST_FILENAME);

	/*
	 * Last line has NO trailing whitespace
	 */

	torture_assert(tctx,
		       file_save(TEST_FILENAME,
				 TEST_DATA_NO_NEWLINE,
				 strlen(TEST_DATA_NO_NEWLINE)),
		       "saving file");

	lines = file_lines_load(TEST_FILENAME, &numlines, 0, mem_ctx);

	torture_assert_int_equal(tctx, numlines, 3, "Lines");

	torture_assert_mem_equal(tctx,
				 lines[0],
				 TEST_LINE1,
				 strlen(TEST_LINE1),
				 "Line 1");

	torture_assert_mem_equal(tctx,
				 lines[1],
				 TEST_LINE2,
				 strlen(TEST_LINE2),
				 "Line 2");

	torture_assert_mem_equal(tctx,
				 lines[2],
				 TEST_LINE3,
				 strlen(TEST_LINE3),
				 "Line 3");

	unlink(TEST_FILENAME);

	/*
	 * Empty file
	 */

	torture_assert(tctx,
		       file_save(TEST_FILENAME,
				 TEST_DATA_EMPTY,
				 strlen(TEST_DATA_EMPTY)),
		       "saving file");

	(void)file_lines_load(TEST_FILENAME, &numlines, 0, mem_ctx);

	torture_assert_int_equal(tctx, numlines, 0, "Lines");

	unlink(TEST_FILENAME);

	/*
	 * Just blank lines
	 */

	torture_assert(tctx,
		       file_save(TEST_FILENAME,
				 TEST_DATA_BLANKS_ONLY,
				 strlen(TEST_DATA_BLANKS_ONLY)),
		       "saving file");

	lines = file_lines_load(TEST_FILENAME, &numlines, 0, mem_ctx);

	torture_assert_int_equal(tctx, numlines, 0, "Lines");

	unlink(TEST_FILENAME);

	/*
	 * Several trailing blank lines
	 */

	torture_assert(tctx,
		       file_save(TEST_FILENAME,
				 TEST_DATA_WITH_TRAILING_BLANKS,
				 strlen(TEST_DATA_WITH_TRAILING_BLANKS)),
		       "saving file");

	lines = file_lines_load(TEST_FILENAME, &numlines, 0, mem_ctx);

	torture_assert_int_equal(tctx, numlines, 3, "Lines");

	torture_assert_mem_equal(tctx,
				 lines[0],
				 TEST_LINE1,
				 strlen(TEST_LINE1),
				 "Line 1");

	torture_assert_mem_equal(tctx,
				 lines[1],
				 TEST_LINE2,
				 strlen(TEST_LINE2),
				 "Line 2");

	torture_assert_mem_equal(tctx,
				 lines[2],
				 TEST_LINE3,
				 strlen(TEST_LINE3),
				 "Line 3");

	unlink(TEST_FILENAME);

	return true;
}

static bool test_afdgets(struct torture_context *tctx)
{
	int fd;
	char *line;
	TALLOC_CTX *mem_ctx = tctx;
	bool ret = false;
	
	torture_assert(tctx, file_save(TEST_FILENAME, (const void *)TEST_DATA, 
							 strlen(TEST_DATA)),
				   "saving file");

	fd = open(TEST_FILENAME, O_RDONLY);
	
	torture_assert(tctx, fd != -1, "opening file");

	line = afdgets(fd, mem_ctx, 8);
	torture_assert_goto(tctx, strcmp(line, TEST_LINE1) == 0, ret, done,
			    "line 1 mismatch");

	line = afdgets(fd, mem_ctx, 8);
	torture_assert_goto(tctx, strcmp(line, TEST_LINE2) == 0, ret, done,
			    "line 2 mismatch");

	line = afdgets(fd, mem_ctx, 8);
	torture_assert_goto(tctx, strcmp(line, TEST_LINE3) == 0, ret, done,
			    "line 3 mismatch");
	ret = true;
done:
	close(fd);

	unlink(TEST_FILENAME);
	return ret;
}

static bool test_file_lines_parse(struct torture_context *tctx)
{
	char **lines;
	int numlines;
	TALLOC_CTX *mem_ctx = tctx;
	char *buf;
	size_t size;

	torture_assert(tctx, file_save(TEST_FILENAME,
				       (const void *)TEST_DATA,
				       strlen(TEST_DATA)),
			"saving file");

	buf = file_load(TEST_FILENAME, &size, 0, mem_ctx);
	torture_assert(tctx, buf, "failed to load file");
	unlink(TEST_FILENAME);

	lines = file_lines_parse(buf,
				 size,
				 &numlines,
				 mem_ctx);
	torture_assert(tctx, lines, "failed to parse lines");

	TALLOC_FREE(lines);
	TALLOC_FREE(buf);
	return true;
}

struct torture_suite *torture_local_util_file(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "file");

	torture_suite_add_simple_test(suite, "file_load_save", 
				      test_file_load_save);

	torture_suite_add_simple_test(suite,
				      "file_lines_load",
				      test_file_lines_load);

	torture_suite_add_simple_test(suite, "afdgets", test_afdgets);

	torture_suite_add_simple_test(suite, "file_lines_parse",
			test_file_lines_parse);

	return suite;
}
