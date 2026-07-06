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

static int path_tool_generic(TALLOC_CTX *mem_ctx,
			     int argc,
			     const char **argv,
			     void *private_data,
			     const char *cmd,
			     const char *(*fn)(void))
{
	struct path_tool_context *ctx = talloc_get_type_abort(
		private_data, struct path_tool_context);

	if (argc != 0) {
		cmdline_usage(ctx->cmdline, cmd);
		return EINVAL;
	}

	printf("%s\n", fn());

	return 0;
}

static int path_tool_append_generic(TALLOC_CTX *mem_ctx,
				    int argc,
				    const char **argv,
				    void *private_data,
				    const char *cmd,
				    char *(*fn)(TALLOC_CTX *mem_ctx,
						const char *name))
{
	struct path_tool_context *ctx = talloc_get_type_abort(
		private_data, struct path_tool_context);
	char *p;

	if (argc != 1) {
		cmdline_usage(ctx->cmdline, cmd);
		return EINVAL;
	}

	p = fn(mem_ctx, argv[0]);
	if (p == NULL) {
		D_ERR("Memory allocation error\n");
		return 1;
	}

	printf("%s\n", p);

	return 0;
}

static int path_tool_pidfile(TALLOC_CTX *mem_ctx,
			     int argc,
			     const char **argv,
			     void *private_data)
{
	int ret = path_tool_append_generic(mem_ctx,
					   argc,
					   argv,
					   private_data,
					   "pidfile",
					   path_pidfile);
	return ret;
}

static int path_tool_socket(TALLOC_CTX *mem_ctx,
			     int argc,
			     const char **argv,
			     void *private_data)
{
	int ret = path_tool_append_generic(mem_ctx,
					   argc,
					   argv,
					   private_data,
					   "socket",
					   path_socket);
	return ret;
}

static int path_tool_datadir(TALLOC_CTX *mem_ctx,
			     int argc,
			     const char **argv,
			     void *private_data)
{
	int ret = path_tool_generic(mem_ctx,
				    argc,
				    argv,
				    private_data,
				    "datadir",
				    path_datadir);
	return ret;
}

static int path_tool_datadir_append(TALLOC_CTX *mem_ctx,
				    int argc,
				    const char **argv,
				    void *private_data)
{
	int ret = path_tool_append_generic(mem_ctx,
					   argc,
					   argv,
					   private_data,
					   "datadir append",
					   path_datadir_append);
	return ret;
}

static int path_tool_etcdir(TALLOC_CTX *mem_ctx,
			    int argc,
			    const char **argv,
			    void *private_data)
{
	int ret = path_tool_generic(mem_ctx,
				    argc,
				    argv,
				    private_data,
				    "etcdir",
				    path_etcdir);
	return ret;
}

static int path_tool_etcdir_append(TALLOC_CTX *mem_ctx,
				   int argc,
				   const char **argv,
				   void *private_data)
{
	int ret = path_tool_append_generic(mem_ctx,
					   argc,
					   argv,
					   private_data,
					   "etcdir append",
					   path_etcdir_append);
	return ret;
}

static int path_tool_lockdir(TALLOC_CTX *mem_ctx,
			     int argc,
			     const char **argv,
			     void *private_data)
{
	int ret = path_tool_generic(mem_ctx,
				    argc,
				    argv,
				    private_data,
				    "lockdir",
				    path_lockdir);
	return ret;
}

static int path_tool_lockdir_append(TALLOC_CTX *mem_ctx,
				    int argc,
				    const char **argv,
				    void *private_data)
{
	int ret = path_tool_append_generic(mem_ctx,
					   argc,
					   argv,
					   private_data,
					   "lockdir append",
					   path_lockdir_append);
	return ret;
}

static int path_tool_piddir(TALLOC_CTX *mem_ctx,
			    int argc,
			    const char **argv,
			    void *private_data)
{
	int ret = path_tool_generic(mem_ctx,
				    argc,
				    argv,
				    private_data,
				    "piddir",
				    path_piddir);
	return ret;
}

static int path_tool_piddir_append(TALLOC_CTX *mem_ctx,
				   int argc,
				   const char **argv,
				   void *private_data)
{
	int ret = path_tool_append_generic(mem_ctx,
					   argc,
					   argv,
					   private_data,
					   "piddir append",
					   path_piddir_append);
	return ret;
}

static int path_tool_rundir(TALLOC_CTX *mem_ctx,
			    int argc,
			    const char **argv,
			    void *private_data)
{
	int ret = path_tool_generic(mem_ctx,
				    argc,
				    argv,
				    private_data,
				    "rundir",
				    path_rundir);
	return ret;
}

static int path_tool_rundir_append(TALLOC_CTX *mem_ctx,
				   int argc,
				   const char **argv,
				   void *private_data)
{
	int ret = path_tool_append_generic(mem_ctx,
					   argc,
					   argv,
					   private_data,
					   "rundir append",
					   path_rundir_append);
	return ret;
}

static int path_tool_socketdir(TALLOC_CTX *mem_ctx,
			       int argc,
			       const char **argv,
			       void *private_data)
{
	int ret = path_tool_generic(mem_ctx,
				    argc,
				    argv,
				    private_data,
				    "socketdir",
				    path_socketdir);
	return ret;
}

static int path_tool_socketdir_append(TALLOC_CTX *mem_ctx,
				      int argc,
				      const char **argv,
				      void *private_data)
{
	int ret = path_tool_append_generic(mem_ctx,
					   argc,
					   argv,
					   private_data,
					   "socketdir append",
					   path_socketdir_append);
	return ret;
}

static int path_tool_vardir(TALLOC_CTX *mem_ctx,
			    int argc,
			    const char **argv,
			    void *private_data)
{
	int ret = path_tool_generic(mem_ctx,
				    argc,
				    argv,
				    private_data,
				    "vardir",
				    path_vardir);
	return ret;
}

static int path_tool_vardir_append(TALLOC_CTX *mem_ctx,
				   int argc,
				   const char **argv,
				   void *private_data)
{
	int ret = path_tool_append_generic(mem_ctx,
					   argc,
					   argv,
					   private_data,
					   "vardir append",
					   path_vardir_append);
	return ret;
}

struct cmdline_command path_commands[] = {
	{
		.name = "config",
		.fn = path_tool_config,
		.msg_help = "Get path of CTDB config file",
		.msg_args = NULL,
	},
	{
		.name = "pidfile",
		.fn = path_tool_pidfile,
		.msg_help = "Get path of CTDB daemon pidfile",
		.msg_args = "<daemon>",
	},
	{
		.name = "socket",
		.fn = path_tool_socket,
		.msg_help = "Get path of CTDB daemon socket",
		.msg_args = "<daemon>",
	},
	{
		.name = "datadir append",
		.fn = path_tool_datadir_append,
		.msg_help = "Get path relative to CTDB DATADIR",
		.msg_args = "<path>",
	},
	{
		.name = "datadir",
		.fn = path_tool_datadir,
		.msg_help = "Get path of CTDB DATADIR",
		.msg_args = NULL,
	},
	{
		.name = "etcdir append",
		.fn = path_tool_etcdir_append,
		.msg_help = "Get path relative to CTDB ETCDIR",
		.msg_args = "<path>",
	},
	{
		.name = "etcdir",
		.fn = path_tool_etcdir,
		.msg_help = "Get path of CTDB ETCDIR",
		.msg_args = NULL,
	},
	{
		.name = "lockdir append",
		.fn = path_tool_lockdir_append,
		.msg_help = "Get path relative to CTDB LOCKDIR",
		.msg_args = "<path>",
	},
	{
		.name = "lockdir",
		.fn = path_tool_lockdir,
		.msg_help = "Get path of CTDB LOCKDIR",
		.msg_args = NULL,
	},
	{
		.name = "piddir append",
		.fn = path_tool_piddir_append,
		.msg_help = "Get path relative to CTDB PIDDIR",
		.msg_args = "<path>",
	},
	{
		.name = "piddir",
		.fn = path_tool_piddir,
		.msg_help = "Get path of CTDB PIDDIR",
		.msg_args = NULL,
	},
	{
		.name = "rundir append",
		.fn = path_tool_rundir_append,
		.msg_help = "Get path relative to CTDB RUNDIR",
		.msg_args = "<path>",
	},
	{
		.name = "rundir",
		.fn = path_tool_rundir,
		.msg_help = "Get path of CTDB RUNDIR",
		.msg_args = NULL,
	},
	{
		.name = "socketdir append",
		.fn = path_tool_socketdir_append,
		.msg_help = "Get path relative to CTDB SOCKETDIR",
		.msg_args = "<path>",
	},
	{
		.name = "socketdir",
		.fn = path_tool_socketdir,
		.msg_help = "Get path of CTDB SOCKETDIR",
		.msg_args = NULL,
	},
	{
		.name = "vardir append",
		.fn = path_tool_vardir_append,
		.msg_help = "Get path relative to CTDB VARDIR",
		.msg_args = "<path>",
	},
	{
		.name = "vardir",
		.fn = path_tool_vardir,
		.msg_help = "Get path of CTDB VARDIR",
		.msg_args = NULL,
	},
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
