/* 
   Tests wrapper for tools/ctdb.c that uses stubs

   Copyright (C) Martin Schwenke 2011

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

#define CTDB_TEST_USE_MAIN
#include "ctdb_test.c"

#include "libctdb_test.c"

struct ctdb_context *ctdb_cmdline_client_foobar(struct tevent_context *ev,
						struct timeval req_timeout)
{
	struct ctdb_context *ret;

	ret = talloc(NULL, struct ctdb_context);

	return ret;
}

const char *ctdb_get_socketname_foobar(struct ctdb_context *ctdb)
{
	return LIBCTDB_TEST_FAKESTATE;
}
