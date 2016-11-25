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

#include <popt.h>
#include <talloc.h>

#include "lib/util/debug.h"

#include "common/logging.h"

#include "tests/src/test_options.h"

static struct test_options _values;

static struct poptOption options_basic[] = {
	{ "socket", 's', POPT_ARG_STRING, &_values.socket, 0,
		"CTDB socket path", "filename" },
	{ "timelimit", 't', POPT_ARG_INT, &_values.timelimit, 0,
		"Time limit (in seconds)" },
	{ "num-nodes", 'n', POPT_ARG_INT, &_values.num_nodes, 0,
		"Number of cluster nodes" },
	{ "debug", 'd', POPT_ARG_STRING, &_values.debugstr, 0,
		"Debug level" },
	{ "interactive", 'i', POPT_ARG_NONE, &_values.interactive, 0,
		"Interactive output" },
	{ NULL }
};

#define TEST_OPTIONS_BASIC \
	{ NULL, 0, POPT_ARG_INCLUDE_TABLE, options_basic, 0, \
		"General options:", NULL },

static struct poptOption options_database[] = {
	{ "database", 'D', POPT_ARG_STRING, &_values.dbname, 0,
		"CTDB database name" },
	{ "key", 'k', POPT_ARG_STRING, &_values.keystr, 0,
		"Name of database key" },
	{ "value", 'v', POPT_ARG_STRING, &_values.valuestr, 0,
		"Value of database key" },
	{ NULL }
};

#define TEST_OPTIONS_DATABASE \
	{ NULL, 0, POPT_ARG_INCLUDE_TABLE, options_database, 0, \
		"Database options:", NULL },

static void set_defaults_basic(struct test_options *opts)
{
	const char *ctdb_socket;

	/* Set default options */
	opts->socket = CTDB_SOCKET;
	opts->timelimit = 10;
	opts->num_nodes = 1;
	opts->debugstr = "ERR";
	opts->interactive = 0;

	ctdb_socket = getenv("CTDB_SOCKET");
	if (ctdb_socket != NULL) {
		opts->socket = ctdb_socket;
	}
}

static void set_defaults_database(struct test_options *opts)
{
	opts->dbname = NULL;
	opts->keystr = NULL;
	opts->valuestr = NULL;
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

	DEBUGLEVEL = log_level;

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
