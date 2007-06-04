/* 
   ctdb tunables code

   Copyright (C) Andrew Tridgell  2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/
#include "includes.h"
#include "../include/ctdb_private.h"

static const struct {
	const char *name;
	size_t offset;
} tunable_map[] = {
	{ "MaxRedirectCount",  offsetof(struct ctdb_tunable, max_redirect_count) },
	{ "SeqnumFrequency",   offsetof(struct ctdb_tunable, seqnum_frequency) },
	{ "ControlTimeout",    offsetof(struct ctdb_tunable, control_timeout) },
	{ "TraverseTimeout",   offsetof(struct ctdb_tunable, traverse_timeout) },
	{ "MonitoringTimeout", offsetof(struct ctdb_tunable, monitoring_timeout) },
	{ "MonitoringLimit",   offsetof(struct ctdb_tunable, monitoring_limit) },
	{ "MaxLACount",        offsetof(struct ctdb_tunable, max_lacount) },
};


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
	int i;

	if (indata.dsize < sizeof(*t) ||
	    t->length > indata.dsize - offsetof(struct ctdb_control_get_tunable, name)) {
		DEBUG(0,("Bad indata in ctdb_control_get_tunable\n"));
		return -1;
	}

	name = talloc_strndup(ctdb, (char*)t->name, t->length);
	CTDB_NO_MEMORY(ctdb, name);

	for (i=0;i<ARRAY_SIZE(tunable_map);i++) {
		if (strcasecmp(name, tunable_map[i].name) == 0) break;
	}
	talloc_free(name);
	
	if (i == ARRAY_SIZE(tunable_map)) {
		return -1;
	}

	val = *(uint32_t *)(tunable_map[i].offset + (uint8_t*)&ctdb->tunable);

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
	struct ctdb_control_set_tunable *t = 
		(struct ctdb_control_set_tunable *)indata.dptr;
	char *name;
	int i;

	if (indata.dsize < sizeof(*t) ||
	    t->length > indata.dsize - offsetof(struct ctdb_control_set_tunable, name)) {
		DEBUG(0,("Bad indata in ctdb_control_set_tunable\n"));
		return -1;
	}

	name = talloc_strndup(ctdb, (char *)t->name, t->length);
	CTDB_NO_MEMORY(ctdb, name);

	for (i=0;i<ARRAY_SIZE(tunable_map);i++) {
		if (strcasecmp(name, tunable_map[i].name) == 0) break;
	}

	talloc_free(name);
	
	if (i == ARRAY_SIZE(tunable_map)) {
		return -1;
	}
	
	*(uint32_t *)(tunable_map[i].offset + (uint8_t*)&ctdb->tunable) = t->value;

	return 0;
}

/*
  list tunables
 */
int32_t ctdb_control_list_tunables(struct ctdb_context *ctdb, TDB_DATA *outdata)
{
	char *list = NULL;
	int i;
	struct ctdb_control_list_tunable *t;

	list = talloc_strdup(outdata, tunable_map[0].name);
	CTDB_NO_MEMORY(ctdb, list);

	for (i=1;i<ARRAY_SIZE(tunable_map);i++) {
		list = talloc_asprintf_append(list, ":%s", tunable_map[i].name);
		CTDB_NO_MEMORY(ctdb, list);		
	}

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
