/*
 *  Unix SMB/CIFS implementation.
 *
 *  Unit test for util.c
 *
 *  Copyright (C) Christof Schmitt 2020
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

#include "lib/util/util.c"
#include <cmocka.h>

struct test_paths {
	char testdir[PATH_MAX];
	char none[PATH_MAX];
	char dir[PATH_MAX];
	mode_t dir_mode;
	char file[PATH_MAX];
	mode_t file_mode;
	char symlink_none[PATH_MAX];
	char symlink_dir[PATH_MAX];
	char symlink_file[PATH_MAX];
};

static int group_setup(void **state)
{
	struct test_paths *paths = NULL;
	char *testdir = NULL;
	int ret, fd;

	umask(0);

	paths = malloc(sizeof(struct test_paths));
	assert_non_null(paths);

	strlcpy(paths->testdir, tmpdir(), sizeof(paths->testdir));
	strlcat(paths->testdir, "/test_util_XXXXXX", sizeof(paths->testdir));
	testdir = mkdtemp(paths->testdir);
	assert_non_null(testdir);

	strlcpy(paths->none, testdir, sizeof(paths->none));
	strlcat(paths->none, "/none", sizeof(paths->none));

	strlcpy(paths->dir, testdir, sizeof(paths->dir));
	strlcat(paths->dir, "/dir", sizeof(paths->dir));
	paths->dir_mode = 0750;
	ret = mkdir(paths->dir, paths->dir_mode);
	assert_return_code(ret, errno);

	strlcpy(paths->file, testdir, sizeof(paths->file));
	strlcat(paths->file, "/file", sizeof(paths->file));
	paths->file_mode = 0640;
	fd = creat(paths->file, paths->file_mode);
	assert_return_code(fd, errno);
	ret = close(fd);
	assert_return_code(ret, errno);

	strlcpy(paths->symlink_none, testdir, sizeof(paths->symlink_none));
	strlcat(paths->symlink_none, "/symlink_none",
		sizeof(paths->symlink_none));
	ret = symlink("/none", paths->symlink_none);
	assert_return_code(ret, errno);

	strlcpy(paths->symlink_dir, testdir, sizeof(paths->symlink_dir));
	strlcat(paths->symlink_dir, "/symlink_dir", sizeof(paths->symlink_dir));
	ret = symlink(paths->dir, paths->symlink_dir);
	assert_return_code(ret, errno);

	strlcpy(paths->symlink_file, testdir, sizeof(paths->symlink_file));
	strlcat(paths->symlink_file, "/symlink_file",
		sizeof(paths->symlink_file));
	ret = symlink(paths->file, paths->symlink_file);
	assert_return_code(ret, errno);

	*state = paths;

	return 0;
}

static int group_teardown(void **state)
{
	struct test_paths *paths = *state;
	int ret;

	return 0;

	ret = rmdir(paths->dir);
	assert_return_code(ret, errno);

	ret = unlink(paths->file);
	assert_return_code(ret, errno);

	ret = unlink(paths->symlink_none);
	assert_return_code(ret, errno);

	ret = unlink(paths->symlink_dir);
	assert_return_code(ret, errno);

	ret = unlink(paths->symlink_file);
	assert_return_code(ret, errno);

	ret = unlink(paths->testdir);
	assert_return_code(ret, errno);

	free(paths);
	return 0;
}

static void test_directory_create_or_exists_none(void **state)
{
	struct test_paths *paths = *state;
	bool b;
	struct stat sbuf;
	int ret;

	b = directory_create_or_exist(paths->none, 0775);
	assert_true(b);

	ret = lstat(paths->none, &sbuf);
	assert_return_code(ret, errno);
	assert_int_equal(sbuf.st_mode & 0777, 0775);
	assert_true(S_ISDIR(sbuf.st_mode));

	ret = rmdir(paths->none);
	assert_return_code(ret, errno);
}

static void test_directory_create_or_exists_dir(void **state)
{
	struct test_paths *paths = *state;
	bool b;
	struct stat sbuf;
	int ret;

	b = directory_create_or_exist(paths->dir, 770);
	assert_true(b);

	ret = lstat(paths->dir, &sbuf);
	assert_return_code(ret, errno);
	assert_int_equal(sbuf.st_mode & 0777, paths->dir_mode);
	assert_true(S_ISDIR(sbuf.st_mode));
}

static void test_directory_create_or_exists_file(void **state)
{
	struct test_paths *paths = *state;
	bool b;
	struct stat sbuf;
	int ret;

	b = directory_create_or_exist(paths->file, 770);
	assert_false(b);

	ret = lstat(paths->file, &sbuf);
	assert_return_code(ret, errno);
	assert_int_equal(sbuf.st_mode & 0777, paths->file_mode);
	assert_true(S_ISREG(sbuf.st_mode));
}

static void test_directory_create_or_exists_symlink_none(void **state)
{
	struct test_paths *paths = *state;
	bool b;
	struct stat sbuf;
	int ret;

	b = directory_create_or_exist(paths->symlink_none, 770);
	assert_false(b);

	ret = lstat(paths->symlink_none, &sbuf);
	assert_return_code(ret, errno);
	assert_int_equal(sbuf.st_mode & 0777, 0777);
	assert_true(S_ISLNK(sbuf.st_mode));
}

static void test_directory_create_or_exists_symlink_dir(void **state)
{
	struct test_paths *paths = *state;
	bool b;
	struct stat sbuf;
	int ret;

	b = directory_create_or_exist(paths->symlink_dir, 770);
	assert_true(b);

	ret = lstat(paths->symlink_dir, &sbuf);
	assert_return_code(ret, errno);
	assert_int_equal(sbuf.st_mode & 0777, 0777);
	assert_true(S_ISLNK(sbuf.st_mode));
}

static void test_directory_create_or_exists_symlink_file(void **state)
{
	struct test_paths *paths = *state;
	bool b;
	struct stat sbuf;
	int ret;

	b = directory_create_or_exist(paths->symlink_file, 770);
	assert_false(b);

	ret = lstat(paths->symlink_file, &sbuf);
	assert_return_code(ret, errno);
	assert_int_equal(sbuf.st_mode & 0777, 0777);
	assert_true(S_ISLNK(sbuf.st_mode));
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_directory_create_or_exists_none),
		cmocka_unit_test(test_directory_create_or_exists_dir),
		cmocka_unit_test(test_directory_create_or_exists_file),
		cmocka_unit_test(test_directory_create_or_exists_symlink_none),
		cmocka_unit_test(test_directory_create_or_exists_symlink_dir),
		cmocka_unit_test(test_directory_create_or_exists_symlink_file),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
