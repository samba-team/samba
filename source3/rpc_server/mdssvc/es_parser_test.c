/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines / ES backend

   Copyright (C) Ralph Boehme			2019

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "rpc_server/mdssvc/mdssvc.h"
#include "rpc_server/mdssvc/mdssvc_es.h"
#include "rpc_server/mdssvc/es_parser.tab.h"
#include "rpc_server/mdssvc/es_mapping.h"

/*
 * Examples:
 *
 * $ ./spotlight2es '_kMDItemGroupId=="11"'
 * ...
 * $ ./spotlight2es '*=="test*"||kMDItemTextContent=="test*"'
 * ...
 */

int main(int argc, char **argv)
{
	TALLOC_CTX *mem_ctx = NULL;
	json_t *mappings = NULL;
	json_error_t json_error;
	char *default_path = NULL;
	const char *path = NULL;
	const char *query_string = NULL;
	const char *path_scope = NULL;
	char *es_query = NULL;
	bool ok;

	if (argc != 2) {
		printf("usage: %s QUERY\n", argv[0]);
		return 1;
	}
	query_string = argv[1];
	path_scope = "/foo/bar";

	lp_load_global(get_dyn_CONFIGFILE());

	mem_ctx = talloc_init("es_parser_test");
	if (mem_ctx == NULL) {
		return 1;
	}

	default_path = talloc_asprintf(mem_ctx,
		"%s/mdssvc/elasticsearch_mappings.json",
		get_dyn_SAMBA_DATADIR());
	if (default_path == NULL) {
		TALLOC_FREE(mem_ctx);
		return 1;
	}

	path = lp_parm_const_string(GLOBAL_SECTION_SNUM,
				    "elasticsearch",
				    "mappings",
				    default_path);
	if (path == NULL) {
		TALLOC_FREE(mem_ctx);
		return 1;
	}

	mappings = json_load_file(path, 0, &json_error);
	if (mappings == NULL) {
		DBG_ERR("Opening mapping file [%s] failed: %s\n",
			path, strerror(errno));
		TALLOC_FREE(mem_ctx);
		return 1;
	}

	ok = map_spotlight_to_es_query(mem_ctx,
					   mappings,
					   path_scope,
					   query_string,
					   &es_query);
	printf("%s\n", ok ? es_query : "*mapping failed*");

	json_decref(mappings);
	talloc_free(mem_ctx);
	return ok ? 0 : 1;
}
