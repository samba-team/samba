/* 
   ldb database library

   Copyright (C) Simo Sorce  2004

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldb timestamps module
 *
 *  Description: add object timestamping functionality
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include <time.h>

struct private_data {
	const char *error_string;
};

static int timestamps_close(struct ldb_module *module)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "timestamps_close\n");
	return ldb_next_close(module);
}

static int timestamps_search(struct ldb_module *module, const char *base,
				  enum ldb_scope scope, const char *expression,
				  const char * const *attrs, struct ldb_message ***res)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "timestamps_search\n");
	return ldb_next_search(module, base, scope, expression, attrs, res);
}

static int timestamps_search_free(struct ldb_module *module, struct ldb_message **res)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "timestamps_search_free\n");
	return ldb_next_search_free(module, res);
}

static int add_time_element(struct ldb_module *module, struct ldb_message *msg, 
			    const char *attr_name, const char *time_string, unsigned int flags)
{
	struct ldb_val *values;
	char *name, *timestr;
	int i;

	for (i = 0; i < msg->num_elements; i++) {
		if (strcasecmp(msg->elements[i].name, attr_name) == 0) {
			return 0;
		}
	}

	msg->elements = talloc_realloc_p(msg, msg->elements, 
					 struct ldb_message_element, msg->num_elements + 1);
	name = talloc_strdup(msg->elements, attr_name);
	timestr = talloc_strdup(msg->elements, time_string);
	values = talloc_p(msg->elements, struct ldb_val);
	if (!msg->elements || !name || !timestr || !values) {
		return -1;
	}

	msg->elements[msg->num_elements].name = name;
	msg->elements[msg->num_elements].flags = flags;
	msg->elements[msg->num_elements].num_values = 1;
	msg->elements[msg->num_elements].values = values;
	msg->elements[msg->num_elements].values[0].data = timestr;
	msg->elements[msg->num_elements].values[0].length = strlen(timestr);

	msg->num_elements += 1;

	return 0;
}

/* add_record: add crateTimestamp/modifyTimestamp attributes */
static int timestamps_add_record(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_message *msg2 = NULL;
	struct tm *tm;
	char *timestr;
	time_t timeval;
	int ret, i;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "timestamps_add_record\n");

	if (msg->dn[0] != '@') { /* do not manipulate our control entries */
		timeval = time(NULL);
	 	tm = gmtime(&timeval);
		if (!tm) {
			return -1;
		}

		msg2 = talloc_p(module, struct ldb_message);
		if (!msg2) {
			return -1;
		}

		/* formatted like: 20040408072012.0Z */
		timestr = talloc_asprintf(msg2, "%04u%02u%02u%02u%02u%02u.0Z",
					  tm->tm_year+1900, tm->tm_mon+1,
					  tm->tm_mday, tm->tm_hour, tm->tm_min,
					  tm->tm_sec);
		if (!timestr) {
			return -1;
		}

		msg2->dn = msg->dn;
		msg2->num_elements = msg->num_elements;
		msg2->private_data = msg->private_data;
		msg2->elements = talloc_array_p(msg2, struct ldb_message_element, msg2->num_elements);
		for (i = 0; i < msg2->num_elements; i++) {
			msg2->elements[i] = msg->elements[i];
		}

		add_time_element(module, msg2, "createTimestamp", timestr, LDB_FLAG_MOD_ADD);
		add_time_element(module, msg2, "modifyTimestamp", timestr, LDB_FLAG_MOD_ADD);
		add_time_element(module, msg2, "whenCreated", timestr, LDB_FLAG_MOD_ADD);
		add_time_element(module, msg2, "whenChanged", timestr, LDB_FLAG_MOD_ADD);
	}

	if (msg2) {
		ret = ldb_next_add_record(module, msg2);
		talloc_free(msg2);
	} else {
		ret = ldb_next_add_record(module, msg);
	}

	return ret;
}

/* modify_record: change modifyTimestamp as well */
static int timestamps_modify_record(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_message *msg2 = NULL;
	struct tm *tm;
	char *timestr;
	time_t timeval;
	int ret, i;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "timestamps_modify_record\n");

	if (msg->dn[0] != '@') { /* do not manipulate our control entries */
		timeval = time(NULL);
 		tm = gmtime(&timeval);
		if (!tm) {
			return -1;
		}

		msg2 = talloc_p(module, struct ldb_message);
		if (!msg2) {
			return -1;
		}

		/* formatted like: 20040408072012.0Z */
		timestr = talloc_asprintf(msg2, 
					"%04u%02u%02u%02u%02u%02u.0Z",
					tm->tm_year+1900, tm->tm_mon+1,
					tm->tm_mday, tm->tm_hour, tm->tm_min,
					tm->tm_sec);
		if (!timestr) {
			return -1;
		}

		msg2->dn = msg->dn;
		msg2->num_elements = msg->num_elements;
		msg2->private_data = msg->private_data;
		msg2->elements = talloc_array_p(msg2, struct ldb_message_element, msg2->num_elements);
		for (i = 0; i < msg2->num_elements; i++) {
			msg2->elements[i] = msg->elements[i];
		}

		add_time_element(module, msg2, "modifyTimestamp", timestr, LDB_FLAG_MOD_REPLACE);
		add_time_element(module, msg2, "whenChanged", timestr, LDB_FLAG_MOD_REPLACE);
	}

	if (msg2) {
		ret = ldb_next_modify_record(module, msg2);
		talloc_free(msg2);
	} else {
		ret = ldb_next_modify_record(module, msg);
	}

	return ret;
}

static int timestamps_delete_record(struct ldb_module *module, const char *dn)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "timestamps_delete_record\n");
	return ldb_next_delete_record(module, dn);
}

static int timestamps_rename_record(struct ldb_module *module, const char *olddn, const char *newdn)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "timestamps_rename_record\n");
	return ldb_next_rename_record(module, olddn, newdn);
}

static int timestamps_lock(struct ldb_module *module, const char *lockname)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "timestamps_lock\n");
	return ldb_next_named_lock(module, lockname);
}

static int timestamps_unlock(struct ldb_module *module, const char *lockname)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "timestamps_unlock\n");
	return ldb_next_named_unlock(module, lockname);
}

/* return extended error information */
static const char *timestamps_errstring(struct ldb_module *module)
{
	struct private_data *data = (struct private_data *)module->private_data;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "timestamps_errstring\n");
	if (data->error_string) {
		const char *error;

		error = data->error_string;
		data->error_string = NULL;
		return error;
	}

	return ldb_next_errstring(module);
}

static const struct ldb_module_ops timestamps_ops = {
	"timestamps",
	timestamps_close, 
	timestamps_search,
	timestamps_search_free,
	timestamps_add_record,
	timestamps_modify_record,
	timestamps_delete_record,
	timestamps_rename_record,
	timestamps_lock,
	timestamps_unlock,
	timestamps_errstring
};


/* the init function */
#ifdef HAVE_DLOPEN_DISABLED
 struct ldb_module *init_module(struct ldb_context *ldb, const char *options[])
#else
struct ldb_module *timestamps_module_init(struct ldb_context *ldb, const char *options[])
#endif
{
	struct ldb_module *ctx;
	struct private_data *data;

	ctx = talloc_p(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	data = talloc_p(ctx, struct private_data);
	if (!data) {
		talloc_free(ctx);
		return NULL;
	}

	data->error_string = NULL;
	ctx->private_data = data;
	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &timestamps_ops;

	return ctx;
}
