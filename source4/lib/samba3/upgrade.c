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
	const char *domainname;
	struct samba3_domainsecrets *domsec;
	int i;
	*msgs = NULL;

	domainname = samba3_get_param(samba3, "global", "workgroup");

	if (domainname == NULL) {
		DEBUG(0, ("No domain name specified in smb.conf!\n"));
		return -1;
	}

	domsec = samba3_find_domainsecrets(samba3, domainname);

	/* Domain */	
	msg = msg_array_add(ldb, msgs, &count);
	/* FIXME: Guess domain DN by taking ldap bind dn? */

	ldb_msg_add_string(ldb, msg, "objectClass", "top");
	ldb_msg_add_string(ldb, msg, "objectClass", "domain");
	ldb_msg_add_string(ldb, msg, "objectSid", dom_sid_string(msg, &domsec->sid));
	ldb_msg_add_string(ldb, msg, "objectGUID", GUID_string(msg, &domsec->guid));
	ldb_msg_add_string(ldb, msg, "name", domainname);
	ldb_msg_add_string(ldb, msg, "oEMInformation", "Provisioned by Samba4 (upgraded from Samba3)");

	/* account policy as well */

	ldb_msg_add_fmt(ldb, msg, "minPwdLength", "%d", samba3->policy.min_password_length);
	ldb_msg_add_fmt(ldb, msg, "pwdHistoryLength", "%d", samba3->policy.password_history);
	ldb_msg_add_fmt(ldb, msg, "minPwdAge", "%d", samba3->policy.minimum_password_age);
	ldb_msg_add_fmt(ldb, msg, "maxPwdAge", "%d", samba3->policy.maximum_password_age);
	ldb_msg_add_fmt(ldb, msg, "lockoutDuration", "%d", samba3->policy.lockout_duration);
	ldb_msg_add_fmt(ldb, msg, "samba3ResetCountMinutes", "%d", samba3->policy.reset_count_minutes);
	ldb_msg_add_fmt(ldb, msg, "samba3UserMustLogonToChangePassword", "%d", samba3->policy.user_must_logon_to_change_password);
	ldb_msg_add_fmt(ldb, msg, "samba3BadLockoutMinutes", "%d", samba3->policy.bad_lockout_minutes);
	ldb_msg_add_fmt(ldb, msg, "samba3DisconnectTime", "%d", samba3->policy.disconnect_time);
	ldb_msg_add_fmt(ldb, msg, "samba3RefuseMachinePwdChange", "%d", samba3->policy.refuse_machine_password_change);
	
	/* Users */
	for (i = 0; i < samba3->samaccount_count; i++) {
		struct samba3_samaccount *sam = &samba3->samaccounts[i];

		msg = msg_array_add(ldb, msgs, &count);
		msg->dn = ldb_dn_build_child(msg, "cn", sam->fullname, domaindn);

		ldb_msg_add_string(ldb, msg, "objectClass", "top");
		ldb_msg_add_string(ldb, msg, "objectClass", "person");
		ldb_msg_add_string(ldb, msg, "objectClass", "user");
		ldb_msg_add_fmt(ldb, msg, "lastLogon", "%d", sam->logon_time);
		ldb_msg_add_fmt(ldb, msg, "lastLogoff", "%d", sam->logoff_time);
		ldb_msg_add_string(ldb, msg, "unixName", sam->username);
		ldb_msg_add_string(ldb, msg, "name", sam->nt_username);
		ldb_msg_add_string(ldb, msg, "cn", sam->fullname);
		ldb_msg_add_string(ldb, msg, "description", sam->acct_desc);
		ldb_msg_add_fmt(ldb, msg, "primaryGroupID", "%d", sam->group_rid); 
		ldb_msg_add_fmt(ldb, msg, "badPwdcount", "%d", sam->bad_password_count);
		ldb_msg_add_fmt(ldb, msg, "logonCount", "%d", sam->logon_count);
		
		ldb_msg_add_string(ldb, msg, "samba3Domain", sam->domain);
		if (sam->dir_drive) 
			ldb_msg_add_string(ldb, msg, "samba3DirDrive", sam->dir_drive);

		if (sam->munged_dial)
			ldb_msg_add_string(ldb, msg, "samba3MungedDial", sam->munged_dial);

		if (sam->homedir)
			ldb_msg_add_string(ldb, msg, "samba3Homedir", sam->homedir);

		if (sam->logon_script)
			ldb_msg_add_string(ldb, msg, "samba3LogonScript", sam->logon_script);

		if (sam->profile_path)
			ldb_msg_add_string(ldb, msg, "samba3ProfilePath", sam->profile_path);

		if (sam->workstations)
			ldb_msg_add_string(ldb, msg, "samba3Workstations", sam->workstations);

		ldb_msg_add_fmt(ldb, msg, "samba3KickOffTime", "%d", sam->kickoff_time);
		ldb_msg_add_fmt(ldb, msg, "samba3BadPwdTime", "%d", sam->bad_password_time);
		ldb_msg_add_fmt(ldb, msg, "samba3PassLastSetTime", "%d", sam->pass_last_set_time);
		ldb_msg_add_fmt(ldb, msg, "samba3PassCanChangeTime", "%d", sam->pass_can_change_time);
		ldb_msg_add_fmt(ldb, msg, "samba3PassMustChangeTime", "%d", sam->pass_must_change_time);
		ldb_msg_add_fmt(ldb, msg, "samba3Rid", "%d", sam->user_rid); 
	
		/* FIXME: Passwords */
	}

	/* Groups */
	for (i = 0; i < samba3->group.groupmap_count; i++) {
		struct samba3_groupmapping *grp = &samba3->group.groupmappings[i];

		msg = msg_array_add(ldb, msgs, &count);

		if (grp->nt_name != NULL) 
			msg->dn = ldb_dn_build_child(msg, "cn", grp->nt_name, domaindn);
		else 
			msg->dn = ldb_dn_build_child(msg, "cn", dom_sid_string(msg, grp->sid), domaindn);

		ldb_msg_add_string(ldb, msg, "objectClass", "top");
		ldb_msg_add_string(ldb, msg, "objectClass", "group");
		ldb_msg_add_string(ldb, msg, "description", grp->comment);
		ldb_msg_add_string(ldb, msg, "cn", grp->nt_name);
		ldb_msg_add_string(ldb, msg, "objectSid", dom_sid_string(msg, grp->sid));
		ldb_msg_add_string(ldb, msg, "unixName", "FIXME");
		ldb_msg_add_fmt(ldb, msg, "samba3SidNameUse", "%d", grp->sid_name_use);
	}

	return count;
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
