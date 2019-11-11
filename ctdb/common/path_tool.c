/*
   path tool

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

#include <talloc.h>

#include "lib/util/debug.h"

#include "common/logging.h"
#include "common/cmdline.h"
#include "common/path.h"
#include "common/path_tool.h"

struct path_tool_context {
	struct cmdline_context *cmdline;
};

static int path_tool_config(TALLOC_CTX *mem_ctx,
			    int argc,
			    const char **argv,
			    void *private_data)
{
	struct path_tool_context *ctx = talloc_get_type_abort(
		private_data, struct path_tool_context);

	if (argc != 0) {
		cmdline_usage(ctx->cmdline, "config");
		return EINVAL;
	}

	printf("%s\n", path_config(mem_ctx));

	return 0;
}

static int path_tool_pidfile(TALLOC_CTX *mem_ctx,
			     int argc,
			     const char **argv,
			     void *private_data)
{
	struct path_tool_context *ctx = talloc_get_type_abort(
		private_data, struct path_tool_context);
	char *p;

	if (argc != 1) {
		cmdline_usage(ctx->cmdline, "pidfile");
		return EINVAL;
	}

	p = path_pidfile(mem_ctx, argv[0]);
	if (p == NULL) {
		D_ERR("Memory allocation error\n");
		return 1;
	}

	printf("%s\n", p);

	return 0;
}

static int path_tool_socket(TALLOC_CTX *mem_ctx,
			     int argc,
			     const char **argv,
			     void *private_data)
{
	struct path_tool_context *ctx = talloc_get_type_abort(
		private_data, struct path_tool_context);
	char *p;

	if (argc != 1) {
		cmdline_usage(ctx->cmdline, "socket");
		return EINVAL;
	}

	p = path_socket(mem_ctx, argv[0]);
	if (p == NULL) {
		D_ERR("Memory allocation error\n");
		return 1;
	}

	printf("%s\n", p);

	return 0;
}

static int path_tool_datadir(TALLOC_CTX *mem_ctx,
			     int argc,
			     const char **argv,
			     void *private_data)
{
	struct path_tool_context *ctx = talloc_get_type_abort(
		private_data, struct path_tool_context);

	if (argc != 0) {
		cmdline_usage(ctx->cmdline, "datadir");
		return EINVAL;
	}

	printf("%s\n", path_datadir());

	return 0;
}

static int path_tool_datadir_append(TALLOC_CTX *mem_ctx,
				    int argc,
				    const char **argv,
				    void *private_data)
{
	struct path_tool_context *ctx = talloc_get_type_abort(
		private_data, struct path_tool_context);
	char *p;

	if (argc != 1) {
		cmdline_usage(ctx->cmdline, "datadir append");
		return EINVAL;
	}

	p = path_datadir_append(mem_ctx, argv[0]);
	if (p == NULL) {
		D_ERR("Memory allocation error\n");
		return 1;
	}

	printf("%s\n", p);

	return 0;
}

static int path_tool_etcdir(TALLOC_CTX *mem_ctx,
			    int argc,
			    const char **argv,
			    void *private_data)
{
	struct path_tool_context *ctx = talloc_get_type_abort(
		private_data, struct path_tool_context);

	if (argc != 0) {
		cmdline_usage(ctx->cmdline, "etcdir");
		return EINVAL;
	}

	printf("%s\n", path_etcdir());

	return 0;
}

static int path_tool_etcdir_append(TALLOC_CTX *mem_ctx,
				   int argc,
				   const char **argv,
				   void *private_data)
{
	struct path_tool_context *ctx = talloc_get_type_abort(
		private_data, struct path_tool_context);
	char *p;

	if (argc != 1) {
		cmdline_usage(ctx->cmdline, "etcdir append");
		return EINVAL;
	}

	p = path_etcdir_append(mem_ctx, argv[0]);
	if (p == NULL) {
		D_ERR("Memory allocation error\n");
		return 1;
	}

	printf("%s\n", p);

	return 0;
}

static int path_tool_rundir(TALLOC_CTX *mem_ctx,
			    int argc,
			    const char **argv,
			    void *private_data)
{
	struct path_tool_context *ctx = talloc_get_type_abort(
		private_data, struct path_tool_context);

	if (argc != 0) {
		cmdline_usage(ctx->cmdline, "rundir");
		return EINVAL;
	}

	printf("%s\n", path_rundir());

	return 0;
}

static int path_tool_rundir_append(TALLOC_CTX *mem_ctx,
				   int argc,
				   const char **argv,
				   void *private_data)
{
	struct path_tool_context *ctx = talloc_get_type_abort(
		private_data, struct path_tool_context);
	char *p;

	if (argc != 1) {
		cmdline_usage(ctx->cmdline, "rundir append");
		return EINVAL;
	}

	p = path_rundir_append(mem_ctx, argv[0]);
	if (p == NULL) {
		D_ERR("Memory allocation error\n");
		return 1;
	}

	printf("%s\n", p);

	return 0;
}

static int path_tool_vardir(TALLOC_CTX *mem_ctx,
			    int argc,
			    const char **argv,
			    void *private_data)
{
	struct path_tool_context *ctx = talloc_get_type_abort(
		private_data, struct path_tool_context);

	if (argc != 0) {
		cmdline_usage(ctx->cmdline, "vardir");
		return EINVAL;
	}

	printf("%s\n", path_vardir());

	return 0;
}

static int path_tool_vardir_append(TALLOC_CTX *mem_ctx,
				   int argc,
				   const char **argv,
				   void *private_data)
{
	struct path_tool_context *ctx = talloc_get_type_abort(
		private_data, struct path_tool_context);
	char *p;

	if (argc != 1) {
		cmdline_usage(ctx->cmdline, "vardir append");
		return EINVAL;
	}

	p = path_vardir_append(mem_ctx, argv[0]);
	if (p == NULL) {
		D_ERR("Memory allocation error\n");
		return 1;
	}

	printf("%s\n", p);

	return 0;
}

struct cmdline_command path_commands[] = {
	{ "config", path_tool_config,
	  "Get path of CTDB config file", NULL },
	{ "pidfile", path_tool_pidfile,
	  "Get path of CTDB daemon pidfile", "<daemon>" },
	{ "socket", path_tool_socket,
	  "Get path of CTDB daemon socket", "<daemon>" },
	{ "datadir append", path_tool_datadir_append,
	  "Get path relative to CTDB DATADIR", "<path>" },
	{ "datadir", path_tool_datadir,
	  "Get path of CTDB DATADIR", NULL },
	{ "etcdir append", path_tool_etcdir_append,
	  "Get path relative to CTDB ETCDIR", "<path>" },
	{ "etcdir", path_tool_etcdir,
	  "Get path of CTDB ETCDIR", NULL },
	{ "rundir append", path_tool_rundir_append,
	  "Get path relative to CTDB RUNDIR", "<path>" },
	{ "rundir", path_tool_rundir,
	  "Get path of CTDB RUNDIR", NULL },
	{ "vardir append", path_tool_vardir_append,
	  "Get path relative to CTDB VARDIR", "<path>" },
	{ "vardir", path_tool_vardir,
	  "Get path of CTDB VARDIR", NULL },
	CMDLINE_TABLEEND
};

int path_tool_init(TALLOC_CTX *mem_ctx,
		   const char *prog,
		   struct poptOption *options,
		   int argc,
		   const char **argv,
		   bool parse_options,
		   struct path_tool_context **result)
{
	struct path_tool_context *ctx;
	int ret;

	ctx = talloc_zero(mem_ctx, struct path_tool_context);
	if (ctx == NULL) {
		D_ERR("Memory allocation error\n");
		return ENOMEM;
	}

	ret = cmdline_init(ctx,
			   prog,
			   options,
			   NULL,
			   path_commands,
			   &ctx->cmdline);
	if (ret != 0) {
		D_ERR("Failed to initialize cmdline, ret=%d\n", ret);
		talloc_free(ctx);
		return ret;
	}

	ret = cmdline_parse(ctx->cmdline, argc, argv, parse_options);
	if (ret != 0) {
		cmdline_usage(ctx->cmdline, NULL);
		talloc_free(ctx);
		return ret;
	}

	*result = ctx;
	return 0;
}

int path_tool_run(struct path_tool_context *ctx, int *result)
{
	return cmdline_run(ctx->cmdline, ctx, result);
}

#ifdef CTDB_PATH_TOOL

int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	struct path_tool_context *ctx;
	int ret, result;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	ret = path_tool_init(mem_ctx,
			     "ctdb-path",
			     NULL,
			     argc,
			     argv,
			     true,
			     &ctx);
	if (ret != 0) {
		talloc_free(mem_ctx);
		exit(1);
	}

	setup_logging("ctdb-path", DEBUG_STDERR);
	debuglevel_set(DEBUG_ERR);

	ret = path_tool_run(ctx, &result);
	if (ret != 0) {
		result = 1;
	}

	talloc_free(mem_ctx);
	exit(result);
}

#endif /* CTDB_PATH_TOOL */
