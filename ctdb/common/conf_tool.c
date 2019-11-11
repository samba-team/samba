/*
   Config options tool

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
#include "common/conf.h"
#include "common/path.h"

#include "common/logging_conf.h"
#include "cluster/cluster_conf.h"
#include "database/database_conf.h"
#include "event/event_conf.h"
#include "failover/failover_conf.h"
#include "server/legacy_conf.h"

#include "common/conf_tool.h"

struct conf_tool_context {
	struct cmdline_context *cmdline;
	const char *conf_file;
	struct conf_context *conf;
};

static int conf_tool_dump(TALLOC_CTX *mem_ctx,
			  int argc,
			  const char **argv,
			  void *private_data)
{
	struct conf_tool_context *ctx = talloc_get_type_abort(
		private_data, struct conf_tool_context);
	int ret;

	if (argc != 0) {
		cmdline_usage(ctx->cmdline, "dump");
		return EINVAL;
	}

	ret = conf_load(ctx->conf, ctx->conf_file, true);
	if (ret != 0 && ret != ENOENT) {
		D_ERR("Failed to load config file %s\n", ctx->conf_file);
		return ret;
	}

	conf_dump(ctx->conf, stdout);
	return 0;
}

static int conf_tool_get(TALLOC_CTX *mem_ctx,
			 int argc,
			 const char **argv,
			 void *private_data)
{
	struct conf_tool_context *ctx = talloc_get_type_abort(
		private_data, struct conf_tool_context);
	const char *section, *option;
	enum conf_type type;
	int ret;
	bool ok;
	const char *s_val = NULL;
	int i_val;
	bool b_val;

	if (argc != 2) {
		cmdline_usage(ctx->cmdline, "get");
		return EINVAL;
	}

	section = argv[0];
	option = argv[1];

	ok = conf_query(ctx->conf, section, option, &type);
	if (!ok) {
		D_ERR("Configuration option [%s] -> \"%s\" not defined\n",
		      section, option);
		return ENOENT;
	}

	ret = conf_load(ctx->conf, ctx->conf_file, true);
	if (ret != 0 && ret != ENOENT) {
		D_ERR("Failed to load config file %s\n", ctx->conf_file);
		return ret;
	}

	switch (type) {
	case CONF_STRING:
		ret = conf_get_string(ctx->conf,
				      section,
				      option,
				      &s_val,
				      NULL);
		break;

	case CONF_INTEGER:
		ret = conf_get_integer(ctx->conf,
				       section,
				       option,
				       &i_val,
				       NULL);
		break;

	case CONF_BOOLEAN:
		ret = conf_get_boolean(ctx->conf,
				       section,
				       option,
				       &b_val,
				       NULL);
		break;

	default:
		D_ERR("Unknown configuration option type\n");
		return EINVAL;
	}

	if (ret != 0) {
		D_ERR("Failed to get configuration option value\n");
		return ret;
	}

	switch (type) {
	case CONF_STRING:
		printf("%s\n", s_val == NULL ? "" : s_val);
		break;

	case CONF_INTEGER:
		printf("%d\n", i_val);
		break;

	case CONF_BOOLEAN:
		printf("%s\n", b_val ? "true" : "false");
		break;
	}

	return 0;
}

static int conf_tool_validate(TALLOC_CTX *mem_ctx,
			      int argc,
			      const char **argv,
			      void *private_data)
{
	struct conf_tool_context *ctx = talloc_get_type_abort(
		private_data, struct conf_tool_context);
	int ret;

	if (argc != 0) {
		cmdline_usage(ctx->cmdline, "validate");
		return EINVAL;
	}

	ret = conf_load(ctx->conf, ctx->conf_file, false);
	if (ret != 0) {
		D_ERR("Failed to load config file %s\n", ctx->conf_file);
		return ret;
	}

	return 0;
}

struct cmdline_command conf_commands[] = {
	{ "dump", conf_tool_dump,
		"Dump configuration", NULL },
	{ "get", conf_tool_get,
		"Get a config value", "<section> <key>" },
	{ "validate", conf_tool_validate,
		"Validate configuration file", NULL },
	CMDLINE_TABLEEND
};

int conf_tool_init(TALLOC_CTX *mem_ctx,
		   const char *prog,
		   struct poptOption *options,
		   int argc,
		   const char **argv,
		   bool parse_options,
		   struct conf_tool_context **result)
{
	struct conf_tool_context *ctx;
	int ret;

	ctx = talloc_zero(mem_ctx, struct conf_tool_context);
	if (ctx == NULL) {
		D_ERR("Memory allocation error\n");
		return ENOMEM;
	}

	ret = cmdline_init(ctx,
			   prog,
			   options,
			   NULL,
			   conf_commands,
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

int conf_tool_run(struct conf_tool_context *ctx, int *result)
{
	int ret;

	ctx->conf_file = path_config(ctx);
	if (ctx->conf_file == NULL) {
		D_ERR("Memory allocation error\n");
		return ENOMEM;
	}

	ret = conf_init(ctx, &ctx->conf);
	if (ret != 0) {
		D_ERR("Failed to initialize config\n");
		return ret;
	}

	/* Call functions to initialize config sections/variables */
	logging_conf_init(ctx->conf, NULL);
	cluster_conf_init(ctx->conf);
	database_conf_init(ctx->conf);
	event_conf_init(ctx->conf);
	failover_conf_init(ctx->conf);
	legacy_conf_init(ctx->conf);

	if (! conf_valid(ctx->conf)) {
		D_ERR("Failed to define configuration options\n");
		return EINVAL;
	}

	ret = cmdline_run(ctx->cmdline, ctx, result);
	return ret;
}

#ifdef CTDB_CONF_TOOL

static struct {
	const char *debug;
} conf_data = {
	.debug = "ERROR",
};

struct poptOption conf_options[] = {
	POPT_AUTOHELP
	{ "debug", 'd', POPT_ARG_STRING, &conf_data.debug, 0,
		"debug level", "ERROR|WARNING|NOTICE|INFO|DEBUG" },
	POPT_TABLEEND
};

int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	struct conf_tool_context *ctx;
	int ret, result;
	int level;
	bool ok;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	ret = conf_tool_init(mem_ctx,
			     "ctdb-config",
			     conf_options,
			     argc,
			     argv,
			     true,
			     &ctx);
	if (ret != 0) {
		talloc_free(mem_ctx);
		exit(1);
	}

	setup_logging("ctdb-config", DEBUG_STDERR);
	ok = debug_level_parse(conf_data.debug, &level);
	if (!ok) {
		level = DEBUG_ERR;
	}
	debuglevel_set(level);

	ret = conf_tool_run(ctx, &result);
	if (ret != 0) {
		result = 1;
	}

	talloc_free(mem_ctx);
	exit(result);
}

#endif /* CTDB_CONF_TOOL */
