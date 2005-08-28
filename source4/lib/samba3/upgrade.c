/* 
   Unix SMB/CIFS implementation.
   Generate ldb_message 's for samba3_*

    Copyright (C) Jelmer Vernooij 	2005
   
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
#include "lib/samba3/samba3.h"
#include "lib/ldb/include/ldb.h"

static struct ldb_message *msg_array_add(struct ldb_context *ctx, struct ldb_message ***msgs, int *count)
{
	struct ldb_message *ret;
	*msgs = talloc_realloc(ctx, *msgs, struct ldb_message *, (*count)+1);

	ret = (*msgs)[*count] = talloc_zero(ctx, struct ldb_message);
	(*count)++;

	return ret;
}

static struct ldb_dn *regkey_to_dn(struct ldb_context *ldb, const char *name)
{
	char *p, *n, *dup;
	struct ldb_dn *ret = ldb_dn_explode(ldb, "hive=NONE");

	p = dup = talloc_strdup(ldb, name);

	while (p) {
		n = strchr(p, '/');
		if (n) { *n = '\0';	n++; }

		ret = ldb_dn_build_child(ldb, "key", p, ret);

		p = n;
	}

	talloc_free(dup);

	return ret;
}

/* Where prefix is any of:
 * - HKLM
 *   HKU
 *   HKCR
 *   HKPD
 *   HKPT
 */

int samba3_upgrade_registry(struct samba3_regdb *regdb, const char *prefix, struct ldb_context *ldb, struct ldb_message ***msgs)
{
	int i;
	struct ldb_message *msg;
	int count = 0;
	char *prefix_up = strupper_talloc(ldb, prefix);
	*msgs = NULL;

	for (i = 0; i < regdb->key_count; i++) {
		int j;
		struct samba3_regkey *rk = &regdb->keys[i];
		struct ldb_dn *keydn;

		/* Only handle selected hive */
		if (strncmp(prefix_up, rk->name, strlen(prefix_up)) != 0) {
			continue;
		}

		msg = msg_array_add(ldb, msgs, &count);

		msg->num_elements = 0;
		msg->elements = NULL;
		msg->private_data = NULL;

		/* Convert key name to dn */
		keydn = msg->dn = regkey_to_dn(ldb, rk->name);

		ldb_msg_add_string(ldb, msg, "name", strrchr(rk->name, '/')?strrchr(rk->name, '/')+1:rk->name);
		
		for (j = 0; j < rk->value_count; j++) {
			struct samba3_regval *rv = &rk->values[j];

			msg = msg_array_add(ldb, msgs, &count);
			msg->dn = ldb_dn_build_child(ldb, "value", rv->name, keydn);

			ldb_msg_add_string(ldb, msg, "value", rv->name);
			ldb_msg_add_fmt(ldb, msg, "type", "%d", rv->type);
			ldb_msg_add_value(ldb, msg, "data", &rv->data);
		}
	}
	
	talloc_free(prefix_up);

	return count;
}

int samba3_upgrade_sam(struct samba3 *samba3, struct ldb_context *ldb, struct ldb_message ***msgs)
{
	int count = 0;
	struct ldb_message *msg;
	struct ldb_dn *domaindn = NULL;
	*msgs = NULL;

	/* Domain */	
	msg = msg_array_add(ldb, msgs, &count);

	/* FIXME: Guess domain DN by taking ldap bind dn? */

	/* FIXME */
	return -1;
}

int samba3_upgrade_winbind(struct samba3 *samba3, struct ldb_context *ldb, struct ldb_message ***msgs)
{
	int i;
	int count = 0;
	struct ldb_message *msg;
	struct ldb_dn *basedn = NULL;
	*msgs = NULL;

	msg = msg_array_add(ldb, msgs, &count);

	msg->dn = basedn; 
	
	ldb_msg_add_fmt(ldb, msg, "userHwm", "%d", samba3->idmap.user_hwm);
	ldb_msg_add_fmt(ldb, msg, "groupHwm", "%d", samba3->idmap.group_hwm);

	for (i = 0; i < samba3->idmap.mapping_count; i++) {
		char *sid = dom_sid_string(msg, samba3->idmap.mappings[i].sid);
		msg = msg_array_add(ldb, msgs, &count);
		
		msg->dn = ldb_dn_build_child(ldb, "SID", sid, basedn);
		ldb_msg_add_string(ldb, msg, "SID", sid);
		ldb_msg_add_fmt(ldb, msg, "type", "%d", samba3->idmap.mappings[i].type);
		ldb_msg_add_fmt(ldb, msg, "unixID", "%u", samba3->idmap.mappings[i].unix_id);
	}
	
	return count;
}

int samba3_upgrade_winsdb(struct samba3 *samba3, struct ldb_context *ldb, struct ldb_message ***msgs)
{
	int i;
	int count = 0;
	
	for (i = 0; i < samba3->winsdb_count; i++) {
		struct samba3_winsdb_entry *e = &samba3->winsdb_entries[i];
		int j;
		struct ldb_message *msg = msg_array_add(ldb, msgs, &count);

		msg->dn = ldb_dn_string_compose(ldb, NULL, "type=%d,name=%s", e->type, e->name);

		ldb_msg_add_string(ldb, msg, "name", e->name);
		ldb_msg_add_fmt(ldb, msg, "type", "%d", e->type);
		ldb_msg_add_string(ldb, msg, "objectClass", "wins");
		ldb_msg_add_fmt(ldb, msg, "nbFlags", "%x", e->nb_flags);
		ldb_msg_add_string(ldb, msg, "expires", 
				  ldap_timestring(msg, e->ttl));

		for (j = 0; j < e->ip_count; j++) {
			ldb_msg_add_string(ldb, msg, "address", sys_inet_ntoa(e->ips[j]));
		}
	}

	return count;
}
