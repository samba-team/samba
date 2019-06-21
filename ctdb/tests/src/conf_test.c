/*
   Configuration file handling on top of tini

   Copyright (C) Amitay Isaacs  2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"

#include <assert.h>

#include "common/conf.c"

static void test1(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct conf_context *conf;
	int ret;
	bool status;

	ret = conf_init(mem_ctx, &conf);
	assert(ret == 0);
	assert(conf != NULL);

	conf_define_section(conf, "section1", NULL);
	status = conf_valid(conf);
	assert(status == true);

	conf_define_section(conf, NULL, NULL);
	status = conf_valid(conf);
	assert(status == false);

	talloc_free(mem_ctx);
}

static void test2(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct conf_context *conf;
	int ret;
	bool status;

	ret = conf_init(mem_ctx, &conf);
	assert(ret == 0);
	assert(conf != NULL);

	conf_define_string(conf, "section1", "key1", "default", NULL);
	status = conf_valid(conf);
	assert(status == false);

	talloc_free(mem_ctx);
}

static void test3(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct conf_context *conf;
	int ret;
	bool status;

	ret = conf_init(mem_ctx, &conf);
	assert(ret == 0);
	assert(conf != NULL);

	conf_define_section(conf, "section1", NULL);
	status = conf_valid(conf);
	assert(status == true);

	conf_define_string(conf, "section1", "key1", NULL, NULL);
	status = conf_valid(conf);
	assert(status == true);

	conf_define_string(conf, "section1", "key1", "value1", NULL);
	status = conf_valid(conf);
	assert(status == false);

	talloc_free(mem_ctx);
}

static void test4(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct conf_context *conf;
	int ret;
	bool status;

	ret = conf_init(mem_ctx, &conf);
	assert(ret == 0);
	assert(conf != NULL);

	conf_define_section(conf, "section1", NULL);
	status = conf_valid(conf);
	assert(status == true);

	conf_define_string(conf, "section1", "key1", NULL, NULL);
	status = conf_valid(conf);
	assert(status == true);

	conf_define_integer(conf, "section1", "key1", 10, NULL);
	status = conf_valid(conf);
	assert(status == false);

	talloc_free(mem_ctx);
}

static void test5(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct conf_context *conf;
	enum conf_type type;
	int ret;
	bool status;
	const char *s_val;
	int i_val;
	bool b_val;

	ret = conf_init(mem_ctx, &conf);
	assert(ret == 0);
	assert(conf != NULL);

	conf_define_section(conf, "section1", NULL);
	status = conf_valid(conf);
	assert(status == true);

	conf_define_string(conf, "section1", "key1", "value1", NULL);
	conf_define_integer(conf, "section1", "key2", 10, NULL);
	conf_define_boolean(conf, "section1", "key3", true, NULL);

	conf_assign_string_pointer(conf, "section1", "key1", &s_val);
	conf_assign_integer_pointer(conf, "section1", "key2", &i_val);
	conf_assign_boolean_pointer(conf, "section1", "key3", &b_val);

	status = conf_valid(conf);
	assert(status == true);

	status = conf_query(conf, "section1", "key1", &type);
	assert(status == true);
	assert(type == CONF_STRING);

	status = conf_query(conf, "section1", "key2", &type);
	assert(status == true);
	assert(type == CONF_INTEGER);

	status = conf_query(conf, "section1", "key3", &type);
	assert(status == true);
	assert(type == CONF_BOOLEAN);

	assert(strcmp(s_val, "value1") == 0);
	assert(i_val == 10);
	assert(b_val == true);

	conf_set_defaults(conf);

	assert(strcmp(s_val, "value1") == 0);
	assert(i_val == 10);
	assert(b_val == true);

	talloc_free(mem_ctx);
}

static void test6(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct conf_context *conf;
	int ret;
	bool status;
	const char *s_val, *s2_val;
	int i_val, i2_val;
	bool b_val, b2_val, is_default;

	ret = conf_init(mem_ctx, &conf);
	assert(ret == 0);
	assert(conf != NULL);

	conf_define_section(conf, "section1", NULL);
	status = conf_valid(conf);
	assert(status == true);

	conf_define_string(conf, "section1", "key1", "default", NULL);
	conf_define_integer(conf, "section1", "key2", 10, NULL);
	conf_define_boolean(conf, "section1", "key3", true, NULL);

	conf_assign_string_pointer(conf, "section1", "key1", &s_val);
	conf_assign_integer_pointer(conf, "section1", "key2", &i_val);
	conf_assign_boolean_pointer(conf, "section1", "key3", &b_val);

	status = conf_valid(conf);
	assert(status == true);

	is_default = false;
	ret = conf_get_string(conf, "section1", "key1", &s2_val, &is_default);
	assert(ret == 0);
	assert(strcmp(s2_val, "default") == 0);
	assert(is_default == true);

	is_default = false;
	ret = conf_get_integer(conf, "section1", "key2", &i2_val, &is_default);
	assert(ret == 0);
	assert(i2_val == 10);
	assert(is_default == true);

	is_default = false;
	ret = conf_get_boolean(conf, "section1", "key3", &b2_val, &is_default);
	assert(ret == 0);
	assert(b2_val == true);
	assert(is_default == true);

	ret = conf_set_string(conf, "section1", "key1", "foobar");
	assert(ret == 0);

	ret = conf_set_integer(conf, "section1", "key2", 20);
	assert(ret == 0);

	ret = conf_set_boolean(conf, "section1", "key3", false);
	assert(ret == 0);

	assert(strcmp(s_val, "foobar") == 0);
	assert(i_val == 20);
	assert(b_val == false);

	is_default = true;
	ret = conf_get_string(conf, "section1", "key1", &s2_val, &is_default);
	assert(ret == 0);
	assert(strcmp(s2_val, "foobar") == 0);
	assert(is_default == false);

	is_default = true;
	ret = conf_get_integer(conf, "section1", "key2", &i2_val, &is_default);
	assert(ret == 0);
	assert(i2_val == 20);
	assert(is_default == false);

	is_default = true;
	ret = conf_get_boolean(conf, "section1", "key3", &b2_val, &is_default);
	assert(ret == 0);
	assert(b2_val == false);
	assert(is_default == false);

	conf_dump(conf, stdout);

	conf_set_defaults(conf);

	assert(strcmp(s_val, "default") == 0);
	assert(i_val == 10);
	assert(b_val == true);

	talloc_free(mem_ctx);
}

static bool test7_validate_string(const char *key,
				  const char *old_value, const char *new_value,
				  enum conf_update_mode mode)
{
	return false;
}

static bool test7_validate_integer(const char *key,
				   int old_value, int new_value,
				   enum conf_update_mode mode)
{
	return false;
}

static bool test7_validate_boolean(const char *key,
				   bool old_value, bool new_value,
				   enum conf_update_mode mode)
{
	return false;
}

static void test7(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct conf_context *conf;
	int ret;
	bool status;
	const char *s_val, *s2_val;
	int i_val, i2_val;
	bool b_val, b2_val;

	ret = conf_init(mem_ctx, &conf);
	assert(ret == 0);
	assert(conf != NULL);

	conf_define_section(conf, "section1", NULL);
	status = conf_valid(conf);
	assert(status == true);

	conf_define_string(conf, "section1", "key1", "default",
			   test7_validate_string);
	conf_define_integer(conf, "section1", "key2", 10,
			    test7_validate_integer);
	conf_define_boolean(conf, "section1", "key3", true,
			    test7_validate_boolean);

	conf_assign_string_pointer(conf, "section1", "key1", &s_val);
	conf_assign_integer_pointer(conf, "section1", "key2", &i_val);
	conf_assign_boolean_pointer(conf, "section1", "key3", &b_val);

	status = conf_valid(conf);
	assert(status == true);

	ret = conf_set_string(conf, "section1", "key1", "default");
	assert(ret == 0);

	ret = conf_set_string(conf, "section1", "key1", "foobar");
	assert(ret == EINVAL);

	ret = conf_set_integer(conf, "section1", "key2", 10);
	assert(ret == 0);

	ret = conf_set_integer(conf, "section1", "key2", 20);
	assert(ret == EINVAL);

	ret = conf_set_boolean(conf, "section1", "key3", true);
	assert(ret == 0);

	ret = conf_set_boolean(conf, "section1", "key3", false);
	assert(ret == EINVAL);

	assert(strcmp(s_val, "default") == 0);
	assert(i_val == 10);
	assert(b_val == true);

	ret = conf_get_string(conf, "section1", "key2", &s2_val, NULL);
	assert(ret == EINVAL);

	ret = conf_get_integer(conf, "section1", "key3", &i2_val, NULL);
	assert(ret == EINVAL);

	ret = conf_get_boolean(conf, "section1", "key1", &b2_val, NULL);
	assert(ret == EINVAL);

	talloc_free(mem_ctx);
}

static bool test8_validate(struct conf_context *conf,
			   const char *section,
			   enum conf_update_mode mode)
{
	return false;
}

static void test8(const char *filename)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct conf_context *conf;
	int ret;
	bool status;

	ret = conf_init(mem_ctx, &conf);
	assert(ret == 0);
	assert(conf != NULL);

	conf_define_section(conf, "section1", test8_validate);
	status = conf_valid(conf);
	assert(status == true);

	conf_define_string(conf, "section1", "key1", "default", NULL);

	status = conf_valid(conf);
	assert(status == true);

	ret = conf_load(conf, filename, true);
	conf_dump(conf, stdout);

	talloc_free(mem_ctx);
	exit(ret);
}

static void test9(const char *filename, bool ignore_unknown)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct conf_context *conf;
	int ret;
	bool status;

	ret = conf_init(mem_ctx, &conf);
	assert(ret == 0);
	assert(conf != NULL);

	conf_define_section(conf, "section1", NULL);

	conf_define_string(conf, "section1", "key1", "value1", NULL);
	conf_define_integer(conf, "section1", "key2", 10, NULL);
	conf_define_boolean(conf, "section1", "key3", true, NULL);

	status = conf_valid(conf);
	assert(status == true);

	conf_set_boolean(conf, "section1", "key3", false);

	ret = conf_load(conf, filename, ignore_unknown);
	conf_dump(conf, stdout);

	talloc_free(mem_ctx);
	exit(ret);
}

static void test11(const char *filename)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	char reload[PATH_MAX];
	struct conf_context *conf;
	int ret;
	bool status;

	ret = snprintf(reload, sizeof(reload), "%s.reload", filename);
	assert((size_t)ret < sizeof(reload));

	ret = conf_init(mem_ctx, &conf);
	assert(ret == 0);
	assert(conf != NULL);

	conf_define_section(conf, "section1", NULL);

	conf_define_string(conf, "section1", "key1", "value1", NULL);
	conf_define_integer(conf, "section1", "key2", 10, NULL);
	conf_define_boolean(conf, "section1", "key3", true, NULL);

	status = conf_valid(conf);
	assert(status == true);

	ret = conf_load(conf, filename, false);
	assert(ret == 0);

	ret = rename(reload, filename);
	assert(ret == 0);

	ret = conf_reload(conf);
	assert(ret == 0);

	conf_dump(conf, stdout);

	talloc_free(mem_ctx);
	exit(ret);
}

int main(int argc, const char **argv)
{
	int num;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <testnum> [<config>]\n", argv[0]);
		exit(1);
	}

	num = atoi(argv[1]);
	if (num > 7 && argc != 3) {
		fprintf(stderr, "Usage: %s <testnum> [<config>]\n", argv[0]);
		exit(1);
	}

	switch (num) {
	case 1:
		test1();
		break;

	case 2:
		test2();
		break;

	case 3:
		test3();
		break;

	case 4:
		test4();
		break;

	case 5:
		test5();
		break;

	case 6:
		test6();
		break;

	case 7:
		test7();
		break;

	case 8:
		test8(argv[2]);
		break;

	case 9:
		test9(argv[2], true);
		break;

	case 10:
		test9(argv[2], false);
		break;

	case 11:
		test11(argv[2]);
		break;
	}

	return 0;
}
