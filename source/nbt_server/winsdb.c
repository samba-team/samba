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
#include "nbt_server/winsdb.h"
#include "lib/ldb/include/ldb.h"
#include "db_wrap.h"
#include "system/time.h"

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
	const char *expr;
	int i;

	expr = talloc_asprintf(tmp_ctx, "dn=NAME=%s", nbt_name_string(tmp_ctx, name));
	if (expr == NULL) goto failed;

	/* find the record in the WINS database */
	ret = ldb_search(winssrv->wins_db->ldb, NULL, LDB_SCOPE_ONELEVEL, expr, NULL, &res);
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
	rec->expire_time    = ldap_string_to_time(ldb_msg_find_string(res[0], "expires", NULL));
	rec->registered_by  = ldb_msg_find_string(res[0], "registeredBy", NULL);
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
	struct ldb_context *ldb = winssrv->wins_db->ldb;
	struct ldb_message *msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) goto failed;

	msg->dn = talloc_asprintf(msg, "NAME=%s", nbt_name_string(msg, rec->name));
	if (msg->dn == NULL) goto failed;
	ret |= ldb_msg_add_fmt(ldb, msg, "active", "%u", rec->state);
	ret |= ldb_msg_add_fmt(ldb, msg, "nbFlags", "0x%04x", rec->nb_flags);
	ret |= ldb_msg_add_string(ldb, msg, "registeredBy", rec->registered_by);
	ret |= ldb_msg_add_string(ldb, msg, "expires", 
				  ldap_timestring(msg, rec->expire_time));
	for (i=0;rec->addresses[i];i++) {
		ret |= ldb_msg_add_string(ldb, msg, "address", rec->addresses[i]);
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
	struct ldb_context *ldb = winssrv->wins_db->ldb;
	struct ldb_message *msg;
	TALLOC_CTX *tmp_ctx = talloc_new(winssrv);
	int ret;

	msg = winsdb_message(winssrv, rec, tmp_ctx);
	if (msg == NULL) goto failed;
	ret = ldb_add(ldb, msg);
	if (ret != 0) goto failed;

	talloc_free(tmp_ctx);
	return NBT_RCODE_OK;

failed:
	talloc_free(tmp_ctx);
	return NBT_RCODE_SVR;
}


/*
  modify a WINS record in the database
*/
uint8_t winsdb_modify(struct wins_server *winssrv, struct winsdb_record *rec)
{
	struct ldb_context *ldb = winssrv->wins_db->ldb;
	struct ldb_message *msg;
	TALLOC_CTX *tmp_ctx = talloc_new(winssrv);
	int ret;
	int i;

	msg = winsdb_message(winssrv, rec, tmp_ctx);
	if (msg == NULL) goto failed;

	for (i=0;i<msg->num_elements;i++) {
		msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
	}

	ret = ldb_modify(ldb, msg);
	if (ret != 0) goto failed;

	talloc_free(tmp_ctx);
	return NBT_RCODE_OK;

failed:
	talloc_free(tmp_ctx);
	return NBT_RCODE_SVR;
}


/*
  delete a WINS record from the database
*/
uint8_t winsdb_delete(struct wins_server *winssrv, struct nbt_name *name)
{
	struct ldb_context *ldb = winssrv->wins_db->ldb;
	TALLOC_CTX *tmp_ctx = talloc_new(winssrv);
	int ret;
	const char *dn;

	dn = talloc_asprintf(tmp_ctx, "NAME=%s", nbt_name_string(tmp_ctx, name));
	if (dn == NULL) goto failed;

	ret = ldb_delete(ldb, dn);
	if (ret != 0) goto failed;

	talloc_free(tmp_ctx);
	return NBT_RCODE_OK;

failed:
	talloc_free(tmp_ctx);
	return NBT_RCODE_SVR;
}


/*
  connect to the WINS database
*/
NTSTATUS winsdb_init(struct wins_server *winssrv)
{
	winssrv->wins_db = ldb_wrap_connect(winssrv, lp_wins_url(), 0, NULL);
	if (winssrv->wins_db == NULL) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	return NT_STATUS_OK;
}
