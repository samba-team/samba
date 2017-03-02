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

#ifndef __TEST_OPTIONS_H__
#define __TEST_OPTIONS_H__

struct test_options {
	/* Basic options */
	const char *socket;
	int timelimit;
	int num_nodes;
	const char *debugstr;
	int interactive;

	/* Database options */
	const char *dbname;
	const char *keystr;
	const char *valuestr;
	const char *dbtype;
};

bool process_options_basic(int argc, const char **argv,
			   const struct test_options **opts);

bool process_options_database(int argc, const char **argv,
			      const struct test_options **opts);

#endif  /* __TEST_OPTIONS_H__ */
