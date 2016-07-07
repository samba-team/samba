/* 
   ctdb tunables code

   Copyright (C) Andrew Tridgell  2007

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
#include "system/network.h"

#include <talloc.h>
#include <tdb.h>

#include "lib/util/debug.h"

#include "ctdb_private.h"

#include "common/common.h"
#include "common/logging.h"
#include "common/tunable.h"

/*
  set all tunables to defaults
 */
void ctdb_tunables_set_defaults(struct ctdb_context *ctdb)
{
	ctdb_tunable_set_defaults(&ctdb->tunable);
}


/*
  get a tunable
 */
int32_t ctdb_control_get_tunable(struct ctdb_context *ctdb, TDB_DATA indata,
				 TDB_DATA *outdata)
{
	struct ctdb_control_get_tunable *t =
		(struct ctdb_control_get_tunable *)indata.dptr;
	char *name;
	uint32_t val;
	bool ret;

	if (indata.dsize < sizeof(*t) ||
	    t->length > indata.dsize - offsetof(struct ctdb_control_get_tunable, name)) {
		DEBUG(DEBUG_ERR,("Bad indata in ctdb_control_get_tunable\n"));
		return -1;
	}

	name = talloc_strndup(ctdb, (char*)t->name, t->length);
	CTDB_NO_MEMORY(ctdb, name);

	ret = ctdb_tunable_get_value(&ctdb->tunable, name, &val);
	talloc_free(name);
	if (! ret) {
		return -EINVAL;
	}

	outdata->dptr = (uint8_t *)talloc(outdata, uint32_t);
	CTDB_NO_MEMORY(ctdb, outdata->dptr);

	*(uint32_t *)outdata->dptr = val;
	outdata->dsize = sizeof(uint32_t);

	return 0;
}


/*
  set a tunable
 */
int32_t ctdb_control_set_tunable(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_tunable_old *t =
		(struct ctdb_tunable_old *)indata.dptr;
	char *name;
	int ret;
	bool obsolete;

	if (indata.dsize < sizeof(*t) ||
	    t->length > indata.dsize - offsetof(struct ctdb_tunable_old, name)) {
		DEBUG(DEBUG_ERR,("Bad indata in ctdb_control_set_tunable\n"));
		return -1;
	}

	name = talloc_strndup(ctdb, (char *)t->name, t->length);
	CTDB_NO_MEMORY(ctdb, name);

	ret = ctdb_tunable_set_value(&ctdb->tunable, name, t->value,
				     &obsolete);
	if (! ret) {
		talloc_free(name);
		return -1;
	}

	if (obsolete) {
		DEBUG(DEBUG_WARNING,
		      ("Setting obsolete tunable \"%s\"\n", name));
		talloc_free(name);
		return 1;
	}

	talloc_free(name);
	return 0;
}

/*
  list tunables
 */
int32_t ctdb_control_list_tunables(struct ctdb_context *ctdb, TDB_DATA *outdata)
{
	char *list = NULL;
	struct ctdb_control_list_tunable *t;

	list = ctdb_tunable_names_to_string(outdata);
	CTDB_NO_MEMORY(ctdb, list);

	outdata->dsize = offsetof(struct ctdb_control_list_tunable, data) +
		strlen(list) + 1;
	outdata->dptr = talloc_size(outdata, outdata->dsize);
	CTDB_NO_MEMORY(ctdb, outdata->dptr);

	t = (struct ctdb_control_list_tunable *)outdata->dptr;
	t->length = strlen(list)+1;

	memcpy(t->data, list, t->length);
	talloc_free(list);

	return 0;
}
