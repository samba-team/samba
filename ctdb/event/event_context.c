/*
   CTDB event daemon - daemon state

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
#include "system/dir.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/dlinklist.h"

#include "common/logging.h"
#include "common/run_event.h"
#include "common/path.h"

#include "event/event_private.h"

struct event_event {
	struct event_event *prev, *next;

	const char *name;
	struct run_event_script_list *script_list;
};

struct event_component {
	struct event_component *prev, *next;

	/* component state */
	const char *name;
	const char *path;
	struct run_event_context *run_ctx;

	/* events list */
	struct event_event *event;
};

struct event_client {
	struct event_client *prev, *next;

	struct sock_client_context *client;
};

struct event_context {
	struct tevent_context *ev;
	struct event_config *config;
	struct run_proc_context *run_proc_ctx;

	const char *script_dir;
	const char *debug_script;

	/* component list */
	struct event_component *component;

	/* client list */
	struct event_client *client;
};

/*
 * event_event functions
 */

static struct event_event *eventd_event_find(struct event_component *comp,
					     const char *event_name)
{
	struct event_event *event;

	if (event_name == NULL) {
		return NULL;
	}

	for (event = comp->event; event != NULL; event = event->next) {
		if (strcmp(event->name, event_name) == 0) {
			return event;
		}
	}

	return NULL;
}

static int eventd_event_add(struct event_component *comp,
			    const char *event_name,
			    struct event_event **result)
{
	struct event_event *event;

	if (event_name == NULL) {
		return EINVAL;
	}

	event = eventd_event_find(comp, event_name);
	if (event != NULL) {
		goto done;
	}

	event = talloc_zero(comp, struct event_event);
	if (event == NULL) {
		return ENOMEM;
	}

	event->name = talloc_strdup(event, event_name);
	if (event->name == NULL) {
		talloc_free(event);
		return ENOMEM;
	}

	DLIST_ADD_END(comp->event, event);

done:
	if (result != NULL) {
		*result = event;
	}
	return 0;
}

static int eventd_event_set(struct event_component *comp,
			    const char *event_name,
			    struct run_event_script_list *script_list)
{
	struct event_event *event = NULL;
	int ret;

	ret = eventd_event_add(comp, event_name, &event);
	if (ret != 0) {
		return ret;
	}

	TALLOC_FREE(event->script_list);
	if (script_list != NULL) {
		event->script_list = talloc_steal(event, script_list);
	}

	return 0;
}

static int eventd_event_get(struct event_component *comp,
			    const char *event_name,
			    struct run_event_script_list **result)
{
	struct event_event *event;

	event = eventd_event_find(comp, event_name);
	if (event == NULL) {
		return EINVAL;
	}

	*result = event->script_list;
	return 0;
}

/*
 * event_component functions
 */

static struct event_component *eventd_component_find(
					struct event_context *eventd,
					const char *comp_name)
{
	struct event_component *comp;

	if (comp_name == NULL) {
		return NULL;
	}

	for (comp = eventd->component; comp != NULL; comp = comp->next) {
		if (strcmp(comp->name, comp_name) == 0) {
			return comp;
		}
	}

	return NULL;
}

static int eventd_component_add(struct event_context *eventd,
				const char *comp_name,
				struct event_component **result)
{
	struct event_component *comp;
	int ret;

	if (comp_name == NULL) {
		return EINVAL;
	}

	comp = eventd_component_find(eventd, comp_name);
	if (comp != NULL) {
		goto done;
	}

	comp = talloc_zero(eventd, struct event_component);
	if (comp == NULL) {
		return ENOMEM;
	}

	comp->name = talloc_strdup(comp, comp_name);
	if (comp->name == NULL) {
		talloc_free(comp);
		return ENOMEM;
	}

	comp->path = talloc_asprintf(comp,
				     "%s/%s",
				     eventd->script_dir,
				     comp_name);
	if (comp->path == NULL) {
		talloc_free(comp);
		return ENOMEM;
	}

	ret = run_event_init(eventd,
			     eventd->run_proc_ctx,
			     comp->path,
			     eventd->debug_script,
			     &comp->run_ctx);
	if (ret != 0) {
		talloc_free(comp);
		return ret;
	}

	DLIST_ADD_END(eventd->component, comp);

done:
	if (result != NULL) {
		*result = comp;
	}
	return 0;
}

/*
 * event_client functions
 */

static struct event_client *eventd_client_find(
					struct event_context *eventd,
					struct sock_client_context *client)
{
	struct event_client *e;

	for (e = eventd->client; e != NULL; e = e->next) {
		if (e->client == client) {
			return e;
		}
	}

	return NULL;
}

int eventd_client_add(struct event_context *eventd,
		      struct sock_client_context *client)
{
	struct event_client *e;

	e = talloc_zero(eventd, struct event_client);
	if (e == NULL) {
		return ENOMEM;
	}

	e->client = client;

	DLIST_ADD_END(eventd->client, e);

	return 0;
}

void eventd_client_del(struct event_context *eventd,
		       struct sock_client_context *client)
{
	struct event_client *e;

	e = eventd_client_find(eventd, client);
	if (e == NULL) {
		return;
	}

	DLIST_REMOVE(eventd->client, e);

	talloc_free(e);
}

bool eventd_client_exists(struct event_context *eventd,
			  struct sock_client_context *client)
{
	struct event_client *e;

	e = eventd_client_find(eventd, client);
	if (e == NULL) {
		return false;
	}

	return true;
}

/* public functions */

int event_context_init(TALLOC_CTX *mem_ctx,
		       struct tevent_context *ev,
		       struct event_config *config,
		       struct event_context **result)
{
	struct event_context *eventd;
	const char *debug_script;
	int ret;

	eventd = talloc_zero(mem_ctx, struct event_context);
	if (eventd == NULL) {
		return ENOMEM;
	}

	eventd->ev = ev;
	eventd->config = config;

	ret = run_proc_init(eventd, ev, &eventd->run_proc_ctx);
	if (ret != 0) {
		talloc_free(eventd);
		return ret;
	}

	eventd->script_dir = path_etcdir_append(eventd, "events");
	if (eventd->script_dir == NULL) {
		talloc_free(eventd);
		return ENOMEM;
	}

	/* FIXME
	status = directory_exist(eventd->script_dir);
	if (! status) {
		talloc_free(eventd);
		return EINVAL;
	}
	*/

	debug_script = event_config_debug_script(config);
	if (debug_script != NULL) {
		eventd->debug_script = path_etcdir_append(eventd,
							  debug_script);
		if (eventd->debug_script == NULL) {
			D_WARNING("Failed to set debug script to %s\n",
				  debug_script);
		}
	}

	*result = eventd;
	return 0;
}

struct event_config *eventd_config(struct event_context *eventd)
{
	return eventd->config;
}

int eventd_run_ctx(struct event_context *eventd,
		   const char *comp_name,
		   struct run_event_context **result)
{
	struct event_component *comp;
	int ret;

	ret = eventd_component_add(eventd, comp_name, &comp);
	if (ret != 0) {
		return ret;
	}

	*result = comp->run_ctx;
	return 0;
}

int eventd_set_event_result(struct event_context *eventd,
			    const char *comp_name,
			    const char *event_name,
			    struct run_event_script_list *script_list)
{
	struct event_component *comp;

	comp = eventd_component_find(eventd, comp_name);
	if (comp == NULL) {
		return ENOENT;
	}

	return eventd_event_set(comp, event_name, script_list);
}

int eventd_get_event_result(struct event_context *eventd,
			    const char *comp_name,
			    const char *event_name,
			    struct run_event_script_list **result)
{
	struct event_component *comp;
	int ret;

	ret = eventd_component_add(eventd, comp_name, &comp);
	if (ret != 0) {
		return ret;
	}

	return eventd_event_get(comp, event_name, result);
}

struct ctdb_event_script_list *eventd_script_list(
				TALLOC_CTX *mem_ctx,
				struct run_event_script_list *script_list)
{
	struct ctdb_event_script_list *value;
	int num_scripts = 0;
	int i;

	value = talloc_zero(mem_ctx, struct ctdb_event_script_list);
	if (value == NULL) {
		return NULL;
	}

	if (script_list != NULL) {
		num_scripts = script_list->num_scripts;
	}

	if (num_scripts <= 0) {
		return value;
	}

	value->script = talloc_array(value,
				     struct ctdb_event_script,
				     num_scripts);
	if (value->script == NULL) {
		goto fail;
	}

	for (i=0; i<num_scripts; i++) {
		struct run_event_script *rscript = &script_list->script[i];
		struct ctdb_event_script *escript = &value->script[i];

		escript->name = talloc_strdup(value, rscript->name);
		if (escript->name == NULL) {
			goto fail;
		}

		escript->begin = rscript->begin;
		escript->end = rscript->end;
		escript->result = rscript->summary;

		if (rscript->output == NULL) {
			escript->output = NULL;
			continue;
		}

		escript->output = talloc_strdup(value, rscript->output);
		if (escript->output == NULL) {
			goto fail;
		}
	}
	value->num_scripts = num_scripts;

	return value;

fail:
	talloc_free(value);
	return NULL;
}
