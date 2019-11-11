/*
   Command line processing tests

   Copyright (C) Amitay Isaacs  2018

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

#include <popt.h>
#include <talloc.h>

#include <assert.h>

#include "common/cmdline.c"

static int dummy_func(TALLOC_CTX *mem_ctx,
		      int argc,
		      const char **argv,
		      void *private_data)
{
	return 0;
}

static struct poptOption dummy_options[] = {
	POPT_TABLEEND
};

static struct cmdline_command dummy_commands[] = {
	CMDLINE_TABLEEND
};

static void test1(void)
{
	TALLOC_CTX *mem_ctx;
	struct cmdline_context *cmdline;
	int ret;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ret = cmdline_init(mem_ctx, NULL, NULL, NULL, NULL, &cmdline);
	assert(ret == EINVAL);

	ret = cmdline_init(mem_ctx, "test1", NULL, NULL, NULL, &cmdline);
	assert(ret == EINVAL);

	ret = cmdline_init(mem_ctx,
			   "test1",
			   dummy_options,
			   NULL,
			   NULL,
			   &cmdline);
	assert(ret == EINVAL);

	talloc_free(mem_ctx);
}

static struct cmdline_command test2_nofunc[] = {
	{ "nofunc", NULL, NULL, NULL },
	CMDLINE_TABLEEND
};

static struct cmdline_command test2_nohelp[] = {
	{ "nohelp", dummy_func, NULL, NULL },
	CMDLINE_TABLEEND
};

static struct cmdline_command test2_long[] = {
	{ "really really long command with lots of words",
	  dummy_func, "long command help",
	  "<and lots of really long long arguments>" },
	CMDLINE_TABLEEND
};

static struct cmdline_command test2_longhelp[] = {
	{ "longhelp", dummy_func,
	  "this is a really really really long help message" \
	  "with lots of words and lots of description",
	  NULL },
	CMDLINE_TABLEEND
};

static struct cmdline_command test2_twowords[] = {
	{ "multiple words", dummy_func, "multiple words help", NULL },
	CMDLINE_TABLEEND
};

static void test2(void)
{
	TALLOC_CTX *mem_ctx;
	struct cmdline_context *cmdline;
	int ret;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ret = cmdline_init(mem_ctx,
			   "test2",
			   NULL,
			   NULL,
			   test2_nofunc,
			   &cmdline);
	assert(ret == EINVAL);

	ret = cmdline_init(mem_ctx,
			   "test2",
			   NULL,
			   NULL,
			   test2_nohelp,
			   &cmdline);
	assert(ret == EINVAL);

	ret = cmdline_init(mem_ctx,
			   "test2",
			   NULL,
			   NULL,
			   test2_long,
			   &cmdline);
	assert(ret == EINVAL);

	ret = cmdline_init(mem_ctx,
			   "test2",
			   NULL,
			   NULL,
			   test2_longhelp,
			   &cmdline);
	assert(ret == EINVAL);

	ret = cmdline_init(mem_ctx,
			   "test2",
			   NULL,
			   NULL,
			   test2_twowords,
			   &cmdline);
	assert(ret == 0);

	talloc_free(mem_ctx);
}

struct {
	const char *str;
} test3_data;

static struct poptOption test3_noname[] = {
	{ NULL, 'o', POPT_ARG_STRING, &test3_data.str, 0,
	  "Noname option", NULL },
	POPT_TABLEEND
};

static struct poptOption test3_notype[] = {
	{ "debug", 'd', POPT_ARG_NONE, NULL, 0,
	  "No argument option", NULL },
	POPT_TABLEEND
};

static struct poptOption test3_noarg[] = {
	{ "debug", 'd', POPT_ARG_STRING, NULL, 0,
	  "No argument option", NULL },
	POPT_TABLEEND
};

static void test3(void)
{
	TALLOC_CTX *mem_ctx;
	struct cmdline_context *cmdline;
	int ret;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ret = cmdline_init(mem_ctx,
			   "test3",
			   test3_noname,
			   NULL,
			   dummy_commands,
			   &cmdline);
	assert(ret == EINVAL);

	ret = cmdline_init(mem_ctx,
			   "test3",
			   test3_notype,
			   NULL,
			   dummy_commands,
			   &cmdline);
	assert(ret == EINVAL);

	ret = cmdline_init(mem_ctx,
			   "test3",
			   test3_noarg,
			   NULL,
			   dummy_commands,
			   &cmdline);
	assert(ret == EINVAL);

	talloc_free(mem_ctx);
}

static int test4_count;
static int test4_value;

static struct poptOption test4_options[] = {
	{ "count", 'c', POPT_ARG_INT, &test4_count, 0,
	  "Option help of length thirty.", NULL },
	{ "value", 'v', POPT_ARG_INT, &test4_value, 0,
	  "Short description", "Value help of length 23" },
	POPT_TABLEEND
};

static struct cmdline_command test4_commands[] = {
	{ "A really really long command", dummy_func,
	  "This is a really long help message",
	  "<a long arguments message>" },
	{ "short command", dummy_func,
	  "short msg for short command", "<short arg msg>" },
	CMDLINE_TABLEEND
};

static void test4(void)
{
	TALLOC_CTX *mem_ctx;
	struct cmdline_context *cmdline;
	int ret;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ret = cmdline_init(mem_ctx,
			   "test4",
			   test4_options,
			   NULL,
			   test4_commands,
			   &cmdline);
	assert(ret == 0);

	cmdline_usage(cmdline, NULL);
	cmdline_usage(cmdline, "short command");

	talloc_free(mem_ctx);
}

static int action_func(TALLOC_CTX *mem_ctx,
		       int argc,
		       const char **argv,
		       void *private_data)
{
	if (argc != 1) {
		return 100;
	}

	printf("%s\n", argv[0]);
	return 200;
}

static struct cmdline_command action_commands[] = {
	{ "action one", dummy_func, "action one help", NULL },
	{ "action two", action_func, "action two help", NULL },
	CMDLINE_TABLEEND
};

static void test5(void)
{
	TALLOC_CTX *mem_ctx;
	struct cmdline_context *cmdline;
	const char *argv1[] = { "test5", "--help" };
	const char *argv2[] = { "test5", "action" };
	const char *argv3[] = { "test5", "action", "--help" };
	const char *argv4[] = { "test5", "action", "one" };
	int ret;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ret = cmdline_init(mem_ctx,
			   "test5",
			   NULL,
			   "Action",
			   action_commands,
			   &cmdline);
	assert(ret == 0);

	ret = cmdline_parse(cmdline, 2, argv1, true);
	assert(ret == EAGAIN);

	ret = cmdline_parse(cmdline, 2, argv2, true);
	assert(ret == ENOENT);

	ret = cmdline_parse(cmdline, 3, argv3, true);
	assert(ret == EAGAIN);

	ret = cmdline_parse(cmdline, 3, argv4, true);
	assert(ret == 0);

	talloc_free(mem_ctx);
}

static void test6(void)
{
	TALLOC_CTX *mem_ctx;
	struct cmdline_context *cmdline;
	const char *argv1[] = { "action", "two" };
	const char *argv2[] = { "action", "two", "arg1" };
	const char *argv3[] = { "action", "two", "arg1", "arg2" };
	int ret, result;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ret = cmdline_init(mem_ctx,
			   "test6",
			   NULL,
			   NULL,
			   action_commands,
			   &cmdline);
	assert(ret == 0);

	ret = cmdline_parse(cmdline, 2, argv1, false);
	assert(ret == 0);

	ret = cmdline_run(cmdline, NULL, &result);
	assert(ret == 0);
	assert(result == 100);

	ret = cmdline_parse(cmdline, 3, argv2, false);
	assert(ret == 0);

	ret = cmdline_run(cmdline, NULL, &result);
	assert(ret == 0);
	assert(result == 200);

	ret = cmdline_parse(cmdline, 4, argv3, false);
	assert(ret == 0);

	ret = cmdline_run(cmdline, NULL, &result);
	assert(ret == 0);
	assert(result == 100);

	talloc_free(mem_ctx);
}

static int test7_func(TALLOC_CTX *mem_ctx,
		      int argc,
		      const char **argv,
		      void *private_data)
{
	assert(argc == 1);

	printf("%s\n", argv[0]);

	return 0;
}

static struct cmdline_command test7_basic_commands[] = {
	{ "cmd1", test7_func, "command one help", NULL },
	{ "cmd2", test7_func, "command two help", NULL },
	CMDLINE_TABLEEND
};

static struct cmdline_command test7_advanced_commands[] = {
	{ "cmd3", test7_func, "command three help", NULL },
	{ "cmd4", test7_func, "command four help", NULL },
	CMDLINE_TABLEEND
};

static struct cmdline_command test7_ultimate_commands[] = {
	{ "cmd5", test7_func, "command five help", NULL },
	{ "cmd6", test7_func, "command six help", NULL },
	CMDLINE_TABLEEND
};

static void test7(void)
{
	TALLOC_CTX *mem_ctx;
	struct cmdline_context *cmdline;
	const char *argv1[] = { "cmd1", "one" };
	const char *argv2[] = { "cmd3", "three" };
	const char *argv3[] = { "cmd6", "six" };
	int ret, result;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ret = cmdline_init(mem_ctx,
			   "test7",
			   NULL,
			   "Basic",
			   test7_basic_commands,
			   &cmdline);
	assert(ret == 0);

	ret = cmdline_add(cmdline, "Advanced", test7_advanced_commands);
	assert(ret == 0);

	ret = cmdline_add(cmdline, "Ultimate", test7_ultimate_commands);
	assert(ret == 0);

	cmdline_usage(cmdline, NULL);

	printf("\n");

	ret = cmdline_parse(cmdline, 2, argv1, false);
	assert(ret == 0);

	ret = cmdline_run(cmdline, NULL, &result);
	assert(ret == 0);
	assert(result == 0);

	ret = cmdline_parse(cmdline, 2, argv2, false);
	assert(ret == 0);

	ret = cmdline_run(cmdline, NULL, &result);
	assert(ret == 0);
	assert(result == 0);

	ret = cmdline_parse(cmdline, 2, argv3, false);
	assert(ret == 0);

	ret = cmdline_run(cmdline, NULL, &result);
	assert(ret == 0);
	assert(result == 0);

	talloc_free(mem_ctx);
}


int main(int argc, const char **argv)
{
	int num;

	if (argc < 2) {
		fprintf(stderr, "Usage %s <testnum>\n", argv[0]);
		exit(1);
	}

	num = atoi(argv[1]);

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
	}

	return 0;
}
