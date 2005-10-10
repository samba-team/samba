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

static int add_time_element(struct ldb_module *module, struct ldb_message *msg, 
			    const char *attr_name, const char *time_string, unsigned int flags)
{
	struct ldb_message_element *attribute = NULL;

	int i;

	for (i = 0; i < msg->num_elements; i++) {
		if (ldb_attr_cmp(msg->elements[i].name, attr_name) == 0) {
			return 0;
		}
	}

	if (ldb_msg_add_string(module->ldb, msg, attr_name, time_string) != 0) {
		return -1;
	}

	for (i = 0; i < msg->num_elements; i++) {
		if (ldb_attr_cmp(attr_name, msg->elements[i].name) == 0) {
			attribute = &msg->elements[i];
			break;
		}
	}

	if (!attribute) {
		return -1;
	}

	attribute->flags = flags;

	return 0;
}

/* timestamps_add: add crateTimestamp/modifyTimestamp attributes */
static int timestamps_add(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.add.message;
	struct ldb_message *msg2 = NULL;
	struct tm *tm;
	char *timestr;
	time_t timeval;
	int ret, i;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "timestamps_add_record\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(msg->dn)) {
		return ldb_next_request(module, req);
	}

	timeval = time(NULL);
 	tm = gmtime(&timeval);
	if (!tm) {
		return -1;
	}

	msg2 = talloc(module, struct ldb_message);
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
	msg2->elements = talloc_array(msg2, struct ldb_message_element, msg2->num_elements);
	for (i = 0; i < msg2->num_elements; i++) {
		msg2->elements[i] = msg->elements[i];
	}

	add_time_element(module, msg2, "createTimestamp", timestr, LDB_FLAG_MOD_ADD);
	add_time_element(module, msg2, "modifyTimestamp", timestr, LDB_FLAG_MOD_ADD);
	add_time_element(module, msg2, "whenCreated", timestr, LDB_FLAG_MOD_ADD);
	add_time_element(module, msg2, "whenChanged", timestr, LDB_FLAG_MOD_ADD);

	if (msg2) {
		req->op.add.message = msg2;
		ret = ldb_next_request(module, req);
		req->op.add.message = msg;

		talloc_free(msg2);
	} else {
		ret = ldb_next_request(module, req);
	}

	return ret;
}

/* timestamps_modify: change modifyTimestamp as well */
static int timestamps_modify(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.mod.message;
	struct ldb_message *msg2 = NULL;
	struct tm *tm;
	char *timestr;
	time_t timeval;
	int ret, i;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "timestamps_modify_record\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(msg->dn)) {
		return ldb_next_request(module, req);
	}

	timeval = time(NULL);
 	tm = gmtime(&timeval);
	if (!tm) {
		return -1;
	}

	msg2 = talloc(module, struct ldb_message);
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
	msg2->elements = talloc_array(msg2, struct ldb_message_element, msg2->num_elements);
	for (i = 0; i < msg2->num_elements; i++) {
		msg2->elements[i] = msg->elements[i];
	}

	add_time_element(module, msg2, "modifyTimestamp", timestr, LDB_FLAG_MOD_REPLACE);
	add_time_element(module, msg2, "whenChanged", timestr, LDB_FLAG_MOD_REPLACE);

	req->op.mod.message = msg2;
	ret = ldb_next_request(module, req);
	req->op.mod.message = msg;

	talloc_free(msg2);

	return ret;
}

static int timestamps_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_ADD:
		return timestamps_add(module, req);

	case LDB_REQ_MODIFY:
		return timestamps_modify(module, req);

	default:
		return ldb_next_request(module, req);

	}
}


static const struct ldb_module_ops timestamps_ops = {
	.name              = "timestamps",
	.request           = timestamps_request
};


/* the init function */
#ifdef HAVE_DLOPEN_DISABLED
 struct ldb_module *init_module(struct ldb_context *ldb, const char *options[])
#else
struct ldb_module *timestamps_module_init(struct ldb_context *ldb, const char *options[])
#endif
{
	struct ldb_module *ctx;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	ctx->private_data = NULL;
	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &timestamps_ops;

	return ctx;
}
