/*
   CTDB tests commandline options

   Copyright (C) Amitay Isaacs  2015

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
#include <popt.h>
#include <talloc.h>

#include "lib/util/debug.h"

#include "common/logging.h"
#include "common/path.h"

#include "tests/src/test_options.h"

static struct test_options _values;

static struct poptOption options_basic[] = {
	{
		.longName   = "socket",
		.shortName  = 's',
		.argInfo    = POPT_ARG_STRING,
		.arg        = &_values.socket,
		.descrip    = "CTDB socket path",
		.argDescrip = "filename",
	},
	{
		.longName   = "timelimit",
		.shortName  = 't',
		.argInfo    = POPT_ARG_INT,
		.arg        = &_values.timelimit,
		.descrip    = "Time limit (in seconds)",
	},
	{
		.longName   = "num-nodes",
		.shortName  = 'n',
		.argInfo    = POPT_ARG_INT,
		.arg        = &_values.num_nodes,
		.descrip    = "Number of cluster nodes",
	},
	{
		.longName   = "debug",
		.shortName  = 'd',
		.argInfo    = POPT_ARG_STRING,
		.arg        = &_values.debugstr,
		.descrip    = "Debug level",
	},
	{
		.longName   = "interactive",
		.shortName  = 'i',
		.argInfo    = POPT_ARG_NONE,
		.arg        = &_values.interactive,
		.val        = 0,
		.descrip    = "Interactive output",
	},
	POPT_TABLEEND
};

#define TEST_OPTIONS_BASIC                            \
	{                                             \
		.argInfo    = POPT_ARG_INCLUDE_TABLE, \
		.arg        = options_basic,          \
		.descrip    = "General options:",     \
	},

static struct poptOption options_database[] = {
	{
		.longName   = "database",
		.shortName  = 'D',
		.argInfo    = POPT_ARG_STRING,
		.arg        = &_values.dbname,
		.descrip    = "CTDB database name",
	},
	{
		.longName   = "key",
		.shortName  = 'k',
		.argInfo    = POPT_ARG_STRING,
		.arg        = &_values.keystr,
		.descrip    = "Name of database key",
	},
	{
		.longName   = "value",
		.shortName  = 'v',
		.argInfo    = POPT_ARG_STRING,
		.arg        = &_values.valuestr,
		.descrip    = "Value of database key",
	},
	{
		.longName   = "dbtype",
		.shortName  = 'T',
		.argInfo    = POPT_ARG_STRING,
		.arg        = &_values.dbtype,
		.descrip    = "CTDB database type",
	},
	POPT_TABLEEND
};

#define TEST_OPTIONS_DATABASE                         \
	{                                             \
		.argInfo    = POPT_ARG_INCLUDE_TABLE, \
		.arg        = options_database,       \
		.descrip    = "Database options:",    \
	},

static void set_defaults_basic(struct test_options *opts)
{
	/* Set default options */
	opts->socket = path_socket(NULL, "ctdbd"); /* leaked */
	assert(opts->socket != NULL);

	opts->timelimit = 10;
	opts->num_nodes = 1;
	opts->debugstr = "ERR";
	opts->interactive = 0;
}

static void set_defaults_database(struct test_options *opts)
{
	opts->dbname = NULL;
	opts->keystr = NULL;
	opts->valuestr = NULL;
	opts->dbtype = "volatile";
}

static bool verify_options_basic(struct test_options *opts)
{
	int log_level;
	bool status;

	status = debug_level_parse(opts->debugstr, &log_level);
	if (! status) {
		fprintf(stderr, "Error: Invalid debug string '%s'\n",
			opts->debugstr);
		return false;
	}

	debuglevel_set(log_level);

	return true;
}

static bool verify_options_database(struct test_options *opts)
{
	if (opts->dbname == NULL) {
		fprintf(stderr, "Error: Please specify database\n");
		return false;
	}
	if (opts->keystr == NULL) {
		fprintf(stderr, "Error: Please specify key name\n");
		return false;
	}

	if ((strcmp(opts->dbtype, "volatile") != 0) &&
	    (strcmp(opts->dbtype, "persistent") != 0) &&
	    (strcmp(opts->dbtype, "replicated") != 0)) {
		return false;
	}

	return true;
}

static bool process_options_common(int argc, const char **argv,
				   struct poptOption *options)
{
	poptContext pc;
	int opt;

	pc = poptGetContext(argv[0], argc, argv, options,
			    POPT_CONTEXT_KEEP_FIRST);
	while ((opt = poptGetNextOpt(pc)) != -1) {
		fprintf(stderr, "Invalid option %s: %s\n",
			poptBadOption(pc, 0), poptStrerror(opt));
		return false;
	}

	return true;
}

bool process_options_basic(int argc, const char **argv,
			   const struct test_options **opts)
{
	struct poptOption options[] = {
		POPT_AUTOHELP
		TEST_OPTIONS_BASIC
		POPT_TABLEEND
	};

	set_defaults_basic(&_values);

	if (! process_options_common(argc, argv, options)) {
		return false;
	}

	if (! verify_options_basic(&_values)) {
		return false;
	}

	*opts = &_values;
	return true;
}

bool process_options_database(int argc, const char **argv,
			      const struct test_options **opts)
{
	struct poptOption options[] = {
		POPT_AUTOHELP
		TEST_OPTIONS_BASIC
		TEST_OPTIONS_DATABASE
		POPT_TABLEEND
	};

	set_defaults_basic(&_values);
	set_defaults_database(&_values);

	if (! process_options_common(argc, argv, options)) {
		return false;
	}

	if (! verify_options_basic(&_values)) {
		return false;
	}
	if (! verify_options_database(&_values)) {
		return false;
	}

	*opts = &_values;
	return true;
}
