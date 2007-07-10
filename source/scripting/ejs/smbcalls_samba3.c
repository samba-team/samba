/* 
   Unix SMB/CIFS implementation.

   provide hooks into smbd C calls from ejs scripts

   Copyright (C) Jelmer Vernooij 2005
   
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
#include "scripting/ejs/smbcalls.h"
#include "lib/appweb/ejs/ejs.h"
#include "lib/samba3/samba3.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_misc.h"


static struct MprVar mprRegistry(struct samba3_regdb *reg)
{
	struct MprVar mpv = mprObject("registry"), ks, vs, k, v;
	int i, j;

	ks = mprArray("array");

	for (i = 0; i < reg->key_count; i++) {
		k = mprObject("regkey");

		mprSetVar(&k, "name", mprString(reg->keys[i].name));

		vs = mprArray("array");
		
		for (j = 0; j < reg->keys[i].value_count; j++) {
			v = mprObject("regval");

			mprSetVar(&v, "name", mprString(reg->keys[i].values[j].name));
			mprSetVar(&v, "type", mprCreateIntegerVar(reg->keys[i].values[j].type));
			mprSetVar(&v, "data", mprDataBlob(reg->keys[i].values[j].data));

			mprAddArray(&vs, j, v);
		}

		mprSetVar(&k, "values", vs);

		mprAddArray(&ks, i, k);
	}

	if (i == 0) {
		mprSetVar(&ks, "length", mprCreateIntegerVar(i));
	}

	mprSetVar(&mpv, "keys", ks);

	return mpv;
}

static struct MprVar mprPolicy(struct samba3_policy *pol)
{
	struct MprVar mpv = mprObject("policy");

	mprSetVar(&mpv, "min_password_length", mprCreateIntegerVar(pol->min_password_length));
	mprSetVar(&mpv, "password_history", mprCreateIntegerVar(pol->password_history));
	mprSetVar(&mpv, "user_must_logon_to_change_password", mprCreateIntegerVar(pol->user_must_logon_to_change_password));
	mprSetVar(&mpv, "maximum_password_age", mprCreateIntegerVar(pol->maximum_password_age));
	mprSetVar(&mpv, "minimum_password_age", mprCreateIntegerVar(pol->minimum_password_age));
	mprSetVar(&mpv, "lockout_duration", mprCreateIntegerVar(pol->lockout_duration));
	mprSetVar(&mpv, "reset_count_minutes", mprCreateIntegerVar(pol->reset_count_minutes));
	mprSetVar(&mpv, "bad_lockout_minutes", mprCreateIntegerVar(pol->bad_lockout_minutes));
	mprSetVar(&mpv, "disconnect_time", mprCreateIntegerVar(pol->disconnect_time));
	mprSetVar(&mpv, "refuse_machine_password_change", mprCreateIntegerVar(pol->refuse_machine_password_change));

	return mpv;
}

static struct MprVar mprIdmapDb(struct samba3_idmapdb *db)
{
	struct MprVar mpv = mprObject("idmapdb"), mps, mp;
	int i;

	mprSetVar(&mpv, "user_hwm", mprCreateIntegerVar(db->user_hwm));
	mprSetVar(&mpv, "group_hwm", mprCreateIntegerVar(db->group_hwm));

	mps = mprArray("array");

	for (i = 0; i < db->mapping_count; i++) {
		char *tmp;
		mp = mprObject("idmap");

		mprSetVar(&mp, "IDMAP_GROUP", mprCreateIntegerVar(IDMAP_GROUP));
		mprSetVar(&mp, "IDMAP_USER", mprCreateIntegerVar(IDMAP_USER));
		mprSetVar(&mp, "type", mprCreateIntegerVar(db->mappings[i].type));
		mprSetVar(&mp, "unix_id", mprCreateIntegerVar(db->mappings[i].unix_id));

		tmp = dom_sid_string(NULL, db->mappings[i].sid);
		mprSetVar(&mp, "sid", mprString(tmp));
		talloc_free(tmp);

		mprAddArray(&mps, i, mp);
	}

	if (i == 0) {
		mprSetVar(&mpv, "length", mprCreateIntegerVar(i));
	}


	mprSetVar(&mpv, "mappings", mps);

	return mpv;
}

static struct MprVar mprGroupMappings(struct samba3_groupdb *db)
{
	struct MprVar mpv = mprArray("array"), g;
	int i;

	for (i = 0; i < db->groupmap_count; i++) {
		char *tmp;
		g = mprObject("group");

		mprSetVar(&g, "gid", mprCreateIntegerVar(db->groupmappings[i].gid));

		tmp = dom_sid_string(NULL, db->groupmappings[i].sid);
		mprSetVar(&g, "sid", mprString(tmp));
		talloc_free(tmp);

		mprSetVar(&g, "sid_name_use", mprCreateIntegerVar(db->groupmappings[i].sid_name_use));
		mprSetVar(&g, "nt_name", mprString(db->groupmappings[i].nt_name));
		mprSetVar(&g, "comment", mprString(db->groupmappings[i].comment));

		mprAddArray(&mpv, i, g);
	}

	if (i == 0) {
		mprSetVar(&mpv, "length", mprCreateIntegerVar(i));
	}


	return mpv;
}

static struct MprVar mprAliases(struct samba3_groupdb *db)
{
	struct MprVar mpv = mprObject("array"), a, am;
	int i, j;

	for (i = 0; i < db->alias_count; i++) {
		char *tmp;
		a = mprObject("alias");

		tmp = dom_sid_string(NULL, db->aliases[i].sid);
		mprSetVar(&a, "sid", mprString(tmp));
		talloc_free(tmp);

		am = mprArray("array");

		for (j = 0; j < db->aliases[i].member_count; j++) {
			tmp = dom_sid_string(NULL, db->aliases[i].members[j]);
			mprAddArray(&am, j, mprString(tmp));
			talloc_free(tmp);
		}

		mprSetVar(&a, "members", am);
	}

	if (i == 0) {
		mprSetVar(&mpv, "length", mprCreateIntegerVar(i));
	}

	return mpv;
}

static struct MprVar mprDomainSecrets(struct samba3_domainsecrets *ds)
{
	struct MprVar v, e = mprObject("domainsecrets");
	char *tmp;
	DATA_BLOB blob;

	mprSetVar(&e, "name", mprString(ds->name));

	tmp = dom_sid_string(NULL, &ds->sid);
	mprSetVar(&e, "sid", mprString(tmp));
	talloc_free(tmp);

	tmp = GUID_string(NULL, &ds->guid);
	mprSetVar(&e, "guid", mprString(tmp));
	talloc_free(tmp);

	mprSetVar(&e, "plaintext_pw", mprString(ds->plaintext_pw));

	mprSetVar(&e, "last_change_time", mprCreateIntegerVar(ds->last_change_time));
	mprSetVar(&e, "sec_channel_type", mprCreateIntegerVar(ds->sec_channel_type));

	v = mprObject("hash_pw");

	blob.data = ds->hash_pw.hash;
	blob.length = 16;
	mprSetVar(&v, "hash", mprDataBlob(blob));

	mprSetVar(&v, "mod_time", mprCreateIntegerVar(ds->hash_pw.mod_time));

	mprSetVar(&e, "hash_pw", v);

	return e;
}

static struct MprVar mprSecrets(struct samba3_secrets *sec)
{
	struct MprVar mpv = mprObject("samba3_secrets"), es, e;
	int i;

	es = mprArray("array");

	for (i = 0; i < sec->ldappw_count; i++) {
		e = mprObject("ldappw");

		mprSetVar(&e, "dn", mprString(sec->ldappws[i].dn));
		mprSetVar(&e, "password", mprString(sec->ldappws[i].password));

		mprAddArray(&es, i, e);
	}

	mprSetVar(&mpv, "ldappws", es);

	es = mprArray("array");

	for (i = 0; i < sec->domain_count; i++) {
		mprAddArray(&es, i, mprDomainSecrets(&sec->domains[i]));
	}

	if (i == 0) {
		mprSetVar(&es, "length", mprCreateIntegerVar(i));
	}

	mprSetVar(&mpv, "domains", es);

	es = mprArray("trusted_domains");

	for (i = 0; i < sec->trusted_domain_count; i++) {
		struct MprVar ns;
		char *tmp;
		int j;
		e = mprObject("trusted_domain");

		ns = mprArray("array");

		for (j = 0; j < sec->trusted_domains[i].uni_name_len; j++) {
			mprAddArray(&ns, j, mprString(sec->trusted_domains[i].uni_name[j]));
		}

		mprSetVar(&e, "uni_name", ns);

		mprSetVar(&e, "pass", mprString(sec->trusted_domains[i].pass));
		mprSetVar(&e, "mod_time", mprCreateIntegerVar(sec->trusted_domains[i].mod_time));

		tmp = dom_sid_string(NULL, &sec->trusted_domains[i].domain_sid);
		mprSetVar(&e, "domains_sid", mprString(tmp));
		talloc_free(tmp);

		mprAddArray(&es, i, e);
	}

	if (i == 0) {
		mprSetVar(&es, "length", mprCreateIntegerVar(i));
	}

	mprSetVar(&mpv, "trusted_domains", es);
	
	es = mprArray("array");

	for (i = 0; i < sec->afs_keyfile_count; i++) {
		struct MprVar ks;
		int j;
		e = mprObject("afs_keyfile");

		mprSetVar(&e, "cell", mprString(sec->afs_keyfiles[i].cell));

		ks = mprArray("array");
		
		for (j = 0; j < 8; j++) {
			struct MprVar k = mprObject("entry");
			DATA_BLOB blob;
			
			mprSetVar(&k, "kvno", mprCreateIntegerVar(sec->afs_keyfiles[i].entry[j].kvno));
			blob.data = (uint8_t*)sec->afs_keyfiles[i].entry[j].key;
			blob.length = 8;
			mprSetVar(&k, "key", mprDataBlob(blob));

			mprAddArray(&ks, j, k);
		}

		mprSetVar(&e, "entry", ks);

		mprSetVar(&e, "nkeys", mprCreateIntegerVar(sec->afs_keyfiles[i].nkeys));

		mprAddArray(&es, i, e);
	}

	if (i == 0) {
		mprSetVar(&es, "length", mprCreateIntegerVar(i));
	}

	mprSetVar(&mpv, "afs_keyfiles", es);

	mprSetVar(&mpv, "ipc_cred", mprCredentials(sec->ipc_cred));

	return mpv;
}

static struct MprVar mprShares(struct samba3 *samba3)
{
	struct MprVar mpv = mprArray("array"), s;
	int i;

	for (i = 0; i < samba3->share_count; i++) {
		s = mprObject("share");

		mprSetVar(&s, "name", mprString(samba3->shares[i].name));

		/* FIXME: secdesc */

		mprAddArray(&mpv, i, s);
	}

	if (i == 0) {
		mprSetVar(&mpv, "length", mprCreateIntegerVar(i));
	}

	return mpv;
}

static struct MprVar mprSamAccounts(struct samba3 *samba3)
{
	struct MprVar mpv = mprArray("array"), m;
	int i;

	for (i = 0; i < samba3->samaccount_count; i++) {
		struct samba3_samaccount *a = &samba3->samaccounts[i];
		DATA_BLOB blob;

		m = mprObject("samba3_samaccount");

		mprSetVar(&m, "logon_time", mprCreateIntegerVar(a->logon_time));
		mprSetVar(&m, "logoff_time", mprCreateIntegerVar(a->logoff_time));
		mprSetVar(&m, "kickoff_time", mprCreateIntegerVar(a->kickoff_time));
		mprSetVar(&m, "bad_password_time", mprCreateIntegerVar(a->bad_password_time));
		mprSetVar(&m, "pass_last_set_time", mprCreateIntegerVar(a->pass_last_set_time));
		mprSetVar(&m, "pass_can_change_time", mprCreateIntegerVar(a->pass_can_change_time));
		mprSetVar(&m, "pass_must_change_time", mprCreateIntegerVar(a->pass_must_change_time));
		mprSetVar(&m, "user_rid", mprCreateIntegerVar(a->user_rid));
		mprSetVar(&m, "group_rid", mprCreateIntegerVar(a->group_rid));
		mprSetVar(&m, "acct_ctrl", mprCreateIntegerVar(a->acct_ctrl));
		mprSetVar(&m, "logon_divs", mprCreateIntegerVar(a->logon_divs));
		mprSetVar(&m, "bad_password_count", mprCreateIntegerVar(a->bad_password_count));
		mprSetVar(&m, "logon_count", mprCreateIntegerVar(a->logon_count));
		mprSetVar(&m, "username", mprString(a->username));
		mprSetVar(&m, "domain", mprString(a->domain));
		mprSetVar(&m, "nt_username", mprString(a->nt_username));
		mprSetVar(&m, "dir_drive", mprString(a->dir_drive));
		mprSetVar(&m, "munged_dial", mprString(a->munged_dial));
		mprSetVar(&m, "fullname", mprString(a->fullname));
		mprSetVar(&m, "homedir", mprString(a->homedir));
		mprSetVar(&m, "logon_script", mprString(a->logon_script));
		mprSetVar(&m, "profile_path", mprString(a->profile_path));
		mprSetVar(&m, "acct_desc", mprString(a->acct_desc));
		mprSetVar(&m, "workstations", mprString(a->workstations));
		blob.length = 16;
		blob.data = a->lm_pw.hash;
		mprSetVar(&m, "lm_pw", mprDataBlob(blob));
		blob.data = a->nt_pw.hash;
		mprSetVar(&m, "nt_pw", mprDataBlob(blob));

		mprAddArray(&mpv, i, m);
	}

	if (i == 0) {
		mprSetVar(&mpv, "length", mprCreateIntegerVar(i));
	}

	return mpv;
}

static struct MprVar mprWinsEntries(struct samba3 *samba3)
{
	struct MprVar mpv = mprArray("array");
	int i, j;

	for (i = 0; i < samba3->winsdb_count; i++) {
		struct MprVar w = mprObject("wins_entry"), ips;

		mprSetVar(&w, "name", mprString(samba3->winsdb_entries[i].name));
		mprSetVar(&w, "nb_flags", mprCreateIntegerVar(samba3->winsdb_entries[i].nb_flags));
		mprSetVar(&w, "type", mprCreateIntegerVar(samba3->winsdb_entries[i].type));
		mprSetVar(&w, "ttl", mprCreateIntegerVar(samba3->winsdb_entries[i].ttl));

		ips = mprObject("array");

		for (j = 0; j < samba3->winsdb_entries[i].ip_count; j++) {
			const char *addr;
			addr = sys_inet_ntoa(samba3->winsdb_entries[i].ips[j]);
			mprAddArray(&ips, j, mprString(addr));
		}

		mprSetVar(&w, "ips", ips);
		
		mprAddArray(&mpv, i, w);
	}

	if (i == 0) {
		mprSetVar(&mpv, "length", mprCreateIntegerVar(i));
	}

	return mpv;
}

static int ejs_find_domainsecrets(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct samba3 *samba3 = NULL;
	struct samba3_domainsecrets *sec;

	if (argc < 1) {
		ejsSetErrorMsg(eid, "find_domainsecrets invalid arguments");
		return -1;
	}

	samba3 = mprGetThisPtr(eid, "samba3");
	mprAssert(samba3);
	sec = samba3_find_domainsecrets(samba3, mprToString(argv[0]));

	if (sec == NULL) {
		mpr_Return(eid, mprCreateUndefinedVar());
	} else {
		mpr_Return(eid, mprDomainSecrets(sec));
	}

	return 0;
}

/*
  initialise samba3 ejs subsystem

  samba3 = samba3_read(libdir,smbconf)
*/
static int ejs_samba3_read(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar mpv = mprObject("samba3");
	struct samba3 *samba3;
	NTSTATUS status;

	if (argc < 2) {
		ejsSetErrorMsg(eid, "samba3_read invalid arguments");
		return -1;
	}

	status = samba3_read(mprToString(argv[0]), mprToString(argv[1]), mprMemCtx(), &samba3);

	if (NT_STATUS_IS_ERR(status)) {
		ejsSetErrorMsg(eid, "samba3_read: error");
		return -1;
	}

	mprAssert(samba3);
	
	mprSetPtrChild(&mpv, "samba3", samba3);
	mprSetVar(&mpv, "winsentries", mprWinsEntries(samba3));
	mprSetVar(&mpv, "samaccounts", mprSamAccounts(samba3));
	mprSetVar(&mpv, "shares", mprShares(samba3));
	mprSetVar(&mpv, "secrets", mprSecrets(&samba3->secrets));
	mprSetVar(&mpv, "groupmappings", mprGroupMappings(&samba3->group));
	mprSetVar(&mpv, "aliases", mprAliases(&samba3->group));
	mprSetVar(&mpv, "idmapdb", mprIdmapDb(&samba3->idmap));
	mprSetVar(&mpv, "policy", mprPolicy(&samba3->policy));
	mprSetVar(&mpv, "registry", mprRegistry(&samba3->registry));
	mprSetVar(&mpv, "configuration", mprParam(samba3->configuration));
	mprSetCFunction(&mpv, "find_domainsecrets", ejs_find_domainsecrets);

	mpr_Return(eid, mpv);
	
	return 0;
}


/*
  setup C functions that be called from ejs
*/
NTSTATUS smb_setup_ejs_samba3(void)
{
	ejsDefineCFunction(-1, "samba3_read", ejs_samba3_read, NULL, MPR_VAR_SCRIPT_HANDLE);
	return NT_STATUS_OK;
}
