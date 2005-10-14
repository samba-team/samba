/* 
   Unix SMB/CIFS implementation.

   WINS database routines

   Copyright (C) Andrew Tridgell	2005
   
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
#include "nbt_server/nbt_server.h"
#include "nbt_server/wins/winsdb.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "db_wrap.h"
#include "system/time.h"

/*
  return the new maxVersion and save it
*/
static uint64_t winsdb_allocate_version(struct wins_server *winssrv)
{
	int ret;
	struct ldb_context *ldb = winssrv->wins_db;
	struct ldb_dn *dn;
	struct ldb_message **res = NULL;
	struct ldb_message *msg = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(winssrv);
	uint64_t maxVersion = 0;

	dn = ldb_dn_explode(tmp_ctx, "CN=VERSION");
	if (!dn) goto failed;

	ret |= ldb_msg_add_string(msg, "objectClass", "winsEntry");
	ret |= ldb_msg_add_fmt(msg, "minVersion", "%llu", winssrv->min_version);
	ret |= ldb_msg_add_fmt(msg, "maxVersion", "%llu", winssrv->max_version);
	if (ret != 0) goto failed;

	if (ret == 1) {
		maxVersion = ldb_msg_find_uint64(res[0], "maxVersion", 0);
	}
	maxVersion++;

	msg = ldb_msg_new(tmp_ctx);
	if (!msg) goto failed;
	msg->dn = dn;


	ret = ldb_msg_add_empty(ldb, msg, "maxVersion", LDB_FLAG_MOD_REPLACE);
	if (ret != 0) goto failed;
	ret = ldb_msg_add_fmt(ldb, msg, "maxVersion", "%llu", maxVersion);
	if (ret != 0) goto failed;

	ret = ldb_modify(ldb, msg);
	if (ret != 0) ret = ldb_add(ldb, msg);
	if (ret != 0) goto failed;

	talloc_free(tmp_ctx);
	return maxVersion;

failed:
	talloc_free(tmp_ctx);
	return 0;
}

/*
  allocate a new version id for a record
*/
static uint64_t winsdb_allocate_version(struct wins_server *winssrv)
{
	winssrv->max_version++;
	if (!winsdb_save_version(winssrv)) {
		return 0;
	}
	return winssrv->max_version;
}

/*
  remove a version id
*/
static BOOL winsdb_remove_version(struct wins_server *winssrv, uint64_t version)
{
	if (version == winssrv->min_version) {
		winssrv->min_version++;
		return winsdb_save_version(winssrv);
	}

	return True;
}


/*
  return a DN for a nbt_name
*/
static struct ldb_dn *winsdb_dn(TALLOC_CTX *mem_ctx, struct nbt_name *name)
{
	struct ldb_dn *dn;

	dn = ldb_dn_string_compose(mem_ctx, NULL, "type=%02x", name->type);
	if (dn && name->name && *name->name) {
		dn = ldb_dn_string_compose(mem_ctx, dn, "name=%s", name->name);
	}
	if (dn && name->scope && *name->scope) {
		dn = ldb_dn_string_compose(mem_ctx, dn, "scope=%s", name->scope);
	}
	return dn;
}

/*
  load a WINS entry from the database
*/
struct winsdb_record *winsdb_load(struct wins_server *winssrv, 
				  struct nbt_name *name, TALLOC_CTX *mem_ctx)
{
	struct ldb_message **res = NULL;
	int ret;
	struct winsdb_record *rec;
	struct ldb_message_element *el;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	int i;

	/* find the record in the WINS database */
	ret = ldb_search(winssrv->wins_db, winsdb_dn(tmp_ctx, name), LDB_SCOPE_BASE, 
			 NULL, NULL, &res);
	if (res != NULL) {
		talloc_steal(tmp_ctx, res);
	}
	if (ret != 1) goto failed;

	rec = talloc(tmp_ctx, struct winsdb_record);
	if (rec == NULL) goto failed;

	/* parse it into a more convenient winsdb_record structure */
	rec->name           = name;
	rec->state          = ldb_msg_find_int(res[0], "active", WINS_REC_RELEASED);
	rec->nb_flags       = ldb_msg_find_int(res[0], "nbFlags", 0);
	rec->expire_time    = ldb_string_to_time(ldb_msg_find_string(res[0], "expires", NULL));
	rec->registered_by  = ldb_msg_find_string(res[0], "registeredBy", NULL);
	rec->version        = ldb_msg_find_uint64(res[0], "version", 0);
	talloc_steal(rec, rec->registered_by);

	el = ldb_msg_find_element(res[0], "address");
	if (el == NULL) goto failed;

	rec->addresses     = talloc_array(rec, const char *, el->num_values+1);
	if (rec->addresses == NULL) goto failed;

	for (i=0;i<el->num_values;i++) {
		rec->addresses[i] = talloc_steal(rec->addresses, el->values[i].data);
	}
	rec->addresses[i] = NULL;

	/* see if it has already expired */
	if (rec->state == WINS_REC_ACTIVE &&
	    rec->expire_time <= time(NULL)) {
		DEBUG(5,("WINS: expiring name %s (expired at %s)\n", 
			 nbt_name_string(tmp_ctx, rec->name), timestring(tmp_ctx, rec->expire_time)));
		rec->state = WINS_REC_RELEASED;
	}

	talloc_steal(mem_ctx, rec);
	talloc_free(tmp_ctx);
	return rec;

failed:
	talloc_free(tmp_ctx);
	return NULL;
}


/*
  form a ldb_message from a winsdb_record
*/
static struct ldb_message *winsdb_message(struct wins_server *winssrv, 
					  struct winsdb_record *rec, TALLOC_CTX *mem_ctx)
{
	int i, ret=0;
	struct ldb_message *msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) goto failed;

	msg->dn = winsdb_dn(msg, rec->name);
	if (msg->dn == NULL) goto failed;
	ret |= ldb_msg_add_fmt(msg, "objectClass", "wins");
	ret |= ldb_msg_add_fmt(msg, "active", "%u", rec->state);
	ret |= ldb_msg_add_fmt(msg, "nbFlags", "0x%04x", rec->nb_flags);
	ret |= ldb_msg_add_string(msg, "registeredBy", rec->registered_by);
	ret |= ldb_msg_add_string(msg, "expires", 
				  ldb_timestring(msg, rec->expire_time));
	ret |= ldb_msg_add_fmt(msg, "version", "%llu", rec->version);
	for (i=0;rec->addresses[i];i++) {
		ret |= ldb_msg_add_string(msg, "address", rec->addresses[i]);
	}
	if (ret != 0) goto failed;
	return msg;

failed:
	talloc_free(msg);
	return NULL;
}

/*
  save a WINS record into the database
*/
uint8_t winsdb_add(struct wins_server *winssrv, struct winsdb_record *rec)
{
	struct ldb_context *ldb = winssrv->wins_db;
	struct ldb_message *msg;
	TALLOC_CTX *tmp_ctx = talloc_new(winssrv);
	int trans = -1;
	int ret = 0;


	trans = ldb_transaction_start(ldb);
	if (trans != LDB_SUCCESS) goto failed;

	rec->version = winsdb_allocate_version(winssrv);
	if (rec->version == 0) goto failed;

	msg = winsdb_message(winssrv, rec, tmp_ctx);
	if (msg == NULL) goto failed;
	ret = ldb_add(ldb, msg);
	if (ret != 0) goto failed;

	trans = ldb_transaction_commit(ldb);
	if (trans != LDB_SUCCESS) goto failed;

	talloc_free(tmp_ctx);
	return NBT_RCODE_OK;

failed:
	if (trans == LDB_SUCCESS) ldb_transaction_cancel(ldb);
	talloc_free(tmp_ctx);
	return NBT_RCODE_SVR;
}


/*
  modify a WINS record in the database
*/
uint8_t winsdb_modify(struct wins_server *winssrv, struct winsdb_record *rec)
{
	struct ldb_context *ldb = winssrv->wins_db;
	struct ldb_message *msg;
	TALLOC_CTX *tmp_ctx = talloc_new(winssrv);
	int trans;
	int ret;
	int i;

	trans = ldb_transaction_start(ldb);
	if (trans != LDB_SUCCESS) goto failed;

	rec->version = winsdb_allocate_version(winssrv);
	if (rec->version == 0) goto failed;

	msg = winsdb_message(winssrv, rec, tmp_ctx);
	if (msg == NULL) goto failed;

	for (i=0;i<msg->num_elements;i++) {
		msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
	}

	ret = ldb_modify(ldb, msg);
	if (ret != 0) goto failed;

	trans = ldb_transaction_commit(ldb);
	if (trans != LDB_SUCCESS) goto failed;

	talloc_free(tmp_ctx);
	return NBT_RCODE_OK;

failed:
	if (trans == LDB_SUCCESS) ldb_transaction_cancel(ldb);
	talloc_free(tmp_ctx);
	return NBT_RCODE_SVR;
}


/*
  delete a WINS record from the database
*/
uint8_t winsdb_delete(struct wins_server *winssrv, struct winsdb_record *rec)
{
	struct ldb_context *ldb = winssrv->wins_db;
	TALLOC_CTX *tmp_ctx = talloc_new(winssrv);
	const struct ldb_dn *dn;
	int trans;
	int ret;

	trans = ldb_transaction_start(ldb);
	if (trans != LDB_SUCCESS) goto failed;

	if(!winsdb_remove_version(winssrv, rec->version))
		goto failed;

	dn = winsdb_dn(tmp_ctx, rec->name);
	if (dn == NULL) goto failed;

	ret = ldb_delete(ldb, dn);
	if (ret != 0) goto failed;

	trans = ldb_transaction_commit(ldb);
	if (trans != LDB_SUCCESS) goto failed;

	talloc_free(tmp_ctx);
	return NBT_RCODE_OK;

failed:
	if (trans == LDB_SUCCESS) ldb_transaction_cancel(ldb);
	talloc_free(tmp_ctx);
	return NBT_RCODE_SVR;
}

struct ldb_context *winsdb_connect(TALLOC_CTX *mem_ctx)
{
	return ldb_wrap_connect(mem_ctx, lp_wins_url(), 0, NULL);
}
