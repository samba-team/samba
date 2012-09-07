/*
   Unix SMB/CIFS implementation.
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Andrew Bartlett      2002
   Copyright (C) Rafal Szczesniak     2002
   Copyright (C) Tim Potter           2001

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

/* the Samba secrets database stores any generated, private information
   such as the local SID and machine trust password */

#include "includes.h"
#include "passdb.h"
#include "../libcli/auth/libcli_auth.h"
#include "secrets.h"
#include "dbwrap/dbwrap.h"
#include "../librpc/ndr/libndr.h"
#include "util_tdb.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

/**
 * Form a key for fetching the domain sid
 *
 * @param domain domain name
 *
 * @return keystring
 **/
static const char *domain_sid_keystr(const char *domain)
{
	char *keystr;

	keystr = talloc_asprintf_strupper_m(talloc_tos(), "%s/%s",
					    SECRETS_DOMAIN_SID, domain);
	SMB_ASSERT(keystr != NULL);
	return keystr;
}

static const char *protect_ids_keystr(const char *domain)
{
	char *keystr;

	keystr = talloc_asprintf_strupper_m(talloc_tos(), "%s/%s",
					    SECRETS_PROTECT_IDS, domain);
	SMB_ASSERT(keystr != NULL);
	return keystr;
}

/* N O T E: never use this outside of passdb modules that store the SID on their own */
bool secrets_mark_domain_protected(const char *domain)
{
	bool ret;

	ret = secrets_store(protect_ids_keystr(domain), "TRUE", 5);
	if (!ret) {
		DEBUG(0, ("Failed to protect the Domain IDs\n"));
	}
	return ret;
}

bool secrets_clear_domain_protection(const char *domain)
{
	bool ret;
	void *protection = secrets_fetch(protect_ids_keystr(domain), NULL);
	
	if (protection) {
		SAFE_FREE(protection);
		ret = secrets_delete(protect_ids_keystr(domain));
		if (!ret) {
			DEBUG(0, ("Failed to remove Domain IDs protection\n"));
		}
		return ret;
	}
	return true;
}

bool secrets_store_domain_sid(const char *domain, const struct dom_sid  *sid)
{
#if _SAMBA_BUILD_ == 4
	char *protect_ids;
#endif
	bool ret;

#if _SAMBA_BUILD_ == 4
	protect_ids = secrets_fetch(protect_ids_keystr(domain), NULL);
	if (protect_ids) {
		if (strncmp(protect_ids, "TRUE", 4)) {
			DEBUG(0, ("Refusing to store a Domain SID, "
				  "it has been marked as protected!\n"));
			SAFE_FREE(protect_ids);
			return false;
		}
	}
	SAFE_FREE(protect_ids);
#endif

	ret = secrets_store(domain_sid_keystr(domain), sid, sizeof(struct dom_sid ));

	/* Force a re-query, in case we modified our domain */
	if (ret)
		reset_global_sam_sid();
	return ret;
}

bool secrets_fetch_domain_sid(const char *domain, struct dom_sid  *sid)
{
	struct dom_sid  *dyn_sid;
	size_t size = 0;

	dyn_sid = (struct dom_sid  *)secrets_fetch(domain_sid_keystr(domain), &size);

	if (dyn_sid == NULL)
		return False;

	if (size != sizeof(struct dom_sid)) {
		SAFE_FREE(dyn_sid);
		return False;
	}

	*sid = *dyn_sid;
	SAFE_FREE(dyn_sid);
	return True;
}

bool secrets_store_domain_guid(const char *domain, struct GUID *guid)
{
#if _SAMBA_BUILD_ == 4
	char *protect_ids;
#endif
	fstring key;

#if _SAMBA_BUILD_ == 4
	protect_ids = secrets_fetch(protect_ids_keystr(domain), NULL);
	if (protect_ids) {
		if (strncmp(protect_ids, "TRUE", 4)) {
			DEBUG(0, ("Refusing to store a Domain SID, "
				  "it has been marked as protected!\n"));
			SAFE_FREE(protect_ids);
			return false;
		}
	}
	SAFE_FREE(protect_ids);
#endif

	slprintf(key, sizeof(key)-1, "%s/%s", SECRETS_DOMAIN_GUID, domain);
	if (!strupper_m(key)) {
		return false;
	}
	return secrets_store(key, guid, sizeof(struct GUID));
}

bool secrets_fetch_domain_guid(const char *domain, struct GUID *guid)
{
	struct GUID *dyn_guid;
	fstring key;
	size_t size = 0;
	struct GUID new_guid;

	slprintf(key, sizeof(key)-1, "%s/%s", SECRETS_DOMAIN_GUID, domain);
	if (!strupper_m(key)) {
		return false;
	}
	dyn_guid = (struct GUID *)secrets_fetch(key, &size);

	if (!dyn_guid) {
		if (lp_server_role() == ROLE_DOMAIN_PDC) {
			new_guid = GUID_random();
			if (!secrets_store_domain_guid(domain, &new_guid))
				return False;
			dyn_guid = (struct GUID *)secrets_fetch(key, &size);
		}
		if (dyn_guid == NULL) {
			return False;
		}
	}

	if (size != sizeof(struct GUID)) {
		DEBUG(1,("UUID size %d is wrong!\n", (int)size));
		SAFE_FREE(dyn_guid);
		return False;
	}

	*guid = *dyn_guid;
	SAFE_FREE(dyn_guid);
	return True;
}

/**
 * Form a key for fetching the machine trust account sec channel type
 *
 * @param domain domain name
 *
 * @return keystring
 **/
static const char *machine_sec_channel_type_keystr(const char *domain)
{
	char *keystr;

	keystr = talloc_asprintf_strupper_m(talloc_tos(), "%s/%s",
					    SECRETS_MACHINE_SEC_CHANNEL_TYPE,
					    domain);
	SMB_ASSERT(keystr != NULL);
	return keystr;
}

/**
 * Form a key for fetching the machine trust account last change time
 *
 * @param domain domain name
 *
 * @return keystring
 **/
static const char *machine_last_change_time_keystr(const char *domain)
{
	char *keystr;

	keystr = talloc_asprintf_strupper_m(talloc_tos(), "%s/%s",
					    SECRETS_MACHINE_LAST_CHANGE_TIME,
					    domain);
	SMB_ASSERT(keystr != NULL);
	return keystr;
}


/**
 * Form a key for fetching the machine previous trust account password
 *
 * @param domain domain name
 *
 * @return keystring
 **/
static const char *machine_prev_password_keystr(const char *domain)
{
	char *keystr;

	keystr = talloc_asprintf_strupper_m(talloc_tos(), "%s/%s",
					    SECRETS_MACHINE_PASSWORD_PREV, domain);
	SMB_ASSERT(keystr != NULL);
	return keystr;
}

/**
 * Form a key for fetching the machine trust account password
 *
 * @param domain domain name
 *
 * @return keystring
 **/
static const char *machine_password_keystr(const char *domain)
{
	char *keystr;

	keystr = talloc_asprintf_strupper_m(talloc_tos(), "%s/%s",
					    SECRETS_MACHINE_PASSWORD, domain);
	SMB_ASSERT(keystr != NULL);
	return keystr;
}

/**
 * Form a key for fetching the machine trust account password
 *
 * @param domain domain name
 *
 * @return stored password's key
 **/
static const char *trust_keystr(const char *domain)
{
	char *keystr;

	keystr = talloc_asprintf_strupper_m(talloc_tos(), "%s/%s",
					    SECRETS_MACHINE_ACCT_PASS, domain);
	SMB_ASSERT(keystr != NULL);
	return keystr;
}

/************************************************************************
 Lock the trust password entry.
************************************************************************/

void *secrets_get_trust_account_lock(TALLOC_CTX *mem_ctx, const char *domain)
{
	struct db_context *db_ctx;
	if (!secrets_init()) {
		return NULL;
	}

	db_ctx = secrets_db_ctx();

	return dbwrap_fetch_locked(
		db_ctx, mem_ctx, string_term_tdb_data(trust_keystr(domain)));
}

/************************************************************************
 Routine to get the default secure channel type for trust accounts
************************************************************************/

enum netr_SchannelType get_default_sec_channel(void)
{
	if (lp_server_role() == ROLE_DOMAIN_BDC ||
	    lp_server_role() == ROLE_DOMAIN_PDC ||
	    lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC) {
		return SEC_CHAN_BDC;
	} else {
		return SEC_CHAN_WKSTA;
	}
}

/************************************************************************
 Routine to get the trust account password for a domain.
 This only tries to get the legacy hashed version of the password.
 The user of this function must have locked the trust password file using
 the above secrets_lock_trust_account_password().
************************************************************************/

bool secrets_fetch_trust_account_password_legacy(const char *domain,
						 uint8_t ret_pwd[16],
						 time_t *pass_last_set_time,
						 enum netr_SchannelType *channel)
{
	struct machine_acct_pass *pass;
	size_t size = 0;

	if (!(pass = (struct machine_acct_pass *)secrets_fetch(
		      trust_keystr(domain), &size))) {
		DEBUG(5, ("secrets_fetch failed!\n"));
		return False;
	}

	if (size != sizeof(*pass)) {
		DEBUG(0, ("secrets were of incorrect size!\n"));
		SAFE_FREE(pass);
		return False;
	}

	if (pass_last_set_time) {
		*pass_last_set_time = pass->mod_time;
	}
	memcpy(ret_pwd, pass->hash, 16);

	if (channel) {
		*channel = get_default_sec_channel();
	}

	SAFE_FREE(pass);
	return True;
}

/************************************************************************
 Routine to get the trust account password for a domain.
 The user of this function must have locked the trust password file using
 the above secrets_lock_trust_account_password().
************************************************************************/

bool secrets_fetch_trust_account_password(const char *domain, uint8_t ret_pwd[16],
					  time_t *pass_last_set_time,
					  enum netr_SchannelType *channel)
{
	char *plaintext;

	plaintext = secrets_fetch_machine_password(domain, pass_last_set_time,
						   channel);
	if (plaintext) {
		DEBUG(4,("Using cleartext machine password\n"));
		E_md4hash(plaintext, ret_pwd);
		SAFE_FREE(plaintext);
		return True;
	}

	return secrets_fetch_trust_account_password_legacy(domain, ret_pwd,
							   pass_last_set_time,
							   channel);
}

/************************************************************************
 Routine to delete the old plaintext machine account password if any
************************************************************************/

static bool secrets_delete_prev_machine_password(const char *domain)
{
	char *oldpass = (char *)secrets_fetch(machine_prev_password_keystr(domain), NULL);
	if (oldpass == NULL) {
		return true;
	}
	SAFE_FREE(oldpass);
	return secrets_delete(machine_prev_password_keystr(domain));
}

/************************************************************************
 Routine to delete the plaintext machine account password, old password,
 sec channel type and last change time from secrets database
************************************************************************/

bool secrets_delete_machine_password_ex(const char *domain)
{
	if (!secrets_delete_prev_machine_password(domain)) {
		return false;
	}
	if (!secrets_delete(machine_password_keystr(domain))) {
		return false;
	}
	if (!secrets_delete(machine_sec_channel_type_keystr(domain))) {
		return false;
	}
	return secrets_delete(machine_last_change_time_keystr(domain));
}

/************************************************************************
 Routine to delete the domain sid
************************************************************************/

bool secrets_delete_domain_sid(const char *domain)
{
	return secrets_delete(domain_sid_keystr(domain));
}

/************************************************************************
 Routine to store the previous machine password (by storing the current password
 as the old)
************************************************************************/

static bool secrets_store_prev_machine_password(const char *domain)
{
	char *oldpass;
	bool ret;

	oldpass = (char *)secrets_fetch(machine_password_keystr(domain), NULL);
	if (oldpass == NULL) {
		return true;
	}
	ret = secrets_store(machine_prev_password_keystr(domain), oldpass, strlen(oldpass)+1);
	SAFE_FREE(oldpass);
	return ret;
}

/************************************************************************
 Routine to set the plaintext machine account password for a realm
 the password is assumed to be a null terminated ascii string.
 Before storing
************************************************************************/

bool secrets_store_machine_password(const char *pass, const char *domain,
				    enum netr_SchannelType sec_channel)
{
	bool ret;
	uint32_t last_change_time;
	uint32_t sec_channel_type;

	if (!secrets_store_prev_machine_password(domain)) {
		return false;
	}

	ret = secrets_store(machine_password_keystr(domain), pass, strlen(pass)+1);
	if (!ret)
		return ret;

	SIVAL(&last_change_time, 0, time(NULL));
	ret = secrets_store(machine_last_change_time_keystr(domain), &last_change_time, sizeof(last_change_time));

	SIVAL(&sec_channel_type, 0, sec_channel);
	ret = secrets_store(machine_sec_channel_type_keystr(domain), &sec_channel_type, sizeof(sec_channel_type));

	return ret;
}

/************************************************************************
 Set the machine trust account password, the old pw and last change
 time, domain SID and salting principals based on values passed in
 (added to supprt the secrets_tdb_sync module on secrets.ldb)
************************************************************************/

bool secrets_store_machine_pw_sync(const char *pass, const char *oldpass, const char *domain,
				   const char *realm,
				   const char *salting_principal, uint32_t supported_enc_types,
				   const struct dom_sid *domain_sid, uint32_t last_change_time,
				   bool delete_join)
{
	bool ret;
	uint8_t last_change_time_store[4];
	TALLOC_CTX *frame = talloc_stackframe();
	void *value;

	if (delete_join) {
		secrets_delete_machine_password_ex(domain);
		secrets_delete_domain_sid(domain);
		TALLOC_FREE(frame);
		return true;
	}

	ret = secrets_store(machine_password_keystr(domain), pass, strlen(pass)+1);
	if (!ret) {
		TALLOC_FREE(frame);
		return ret;
	}

	if (oldpass) {
		ret = secrets_store(machine_prev_password_keystr(domain), oldpass, strlen(oldpass)+1);
	} else {
		value = secrets_fetch_prev_machine_password(domain);
		if (value) {
			SAFE_FREE(value);
			ret = secrets_delete_prev_machine_password(domain);
		}
	}
	if (!ret) {
		TALLOC_FREE(frame);
		return ret;
	}

	/* We delete this and instead have the read code fall back to
	 * a default based on server role, as our caller can't specify
	 * this with any more certainty */
	value = secrets_fetch(machine_sec_channel_type_keystr(domain), NULL);
	if (value) {
		SAFE_FREE(value);
		ret = secrets_delete(machine_sec_channel_type_keystr(domain));
		if (!ret) {
			TALLOC_FREE(frame);
			return ret;
		}
	}

	SIVAL(&last_change_time_store, 0, last_change_time);
	ret = secrets_store(machine_last_change_time_keystr(domain),
			    &last_change_time_store, sizeof(last_change_time));

	if (!ret) {
		TALLOC_FREE(frame);
		return ret;
	}

	ret = secrets_store_domain_sid(domain, domain_sid);

	if (!ret) {
		TALLOC_FREE(frame);
		return ret;
	}

	if (realm && salting_principal) {
		char *key = talloc_asprintf(frame, "%s/DES/%s", SECRETS_SALTING_PRINCIPAL, realm);
		if (!key) {
			TALLOC_FREE(frame);
			return false;
		}
		ret = secrets_store(key, salting_principal, strlen(salting_principal)+1 );
	}

	TALLOC_FREE(frame);
	return ret;
}


/************************************************************************
 Routine to fetch the previous plaintext machine account password for a realm
 the password is assumed to be a null terminated ascii string.
************************************************************************/

char *secrets_fetch_prev_machine_password(const char *domain)
{
	return (char *)secrets_fetch(machine_prev_password_keystr(domain), NULL);
}

/************************************************************************
 Routine to fetch the plaintext machine account password for a realm
 the password is assumed to be a null terminated ascii string.
************************************************************************/

char *secrets_fetch_machine_password(const char *domain,
				     time_t *pass_last_set_time,
				     enum netr_SchannelType *channel)
{
	char *ret;
	ret = (char *)secrets_fetch(machine_password_keystr(domain), NULL);

	if (pass_last_set_time) {
		size_t size;
		uint32_t *last_set_time;
		last_set_time = (unsigned int *)secrets_fetch(machine_last_change_time_keystr(domain), &size);
		if (last_set_time) {
			*pass_last_set_time = IVAL(last_set_time,0);
			SAFE_FREE(last_set_time);
		} else {
			*pass_last_set_time = 0;
		}
	}

	if (channel) {
		size_t size;
		uint32_t *channel_type;
		channel_type = (unsigned int *)secrets_fetch(machine_sec_channel_type_keystr(domain), &size);
		if (channel_type) {
			*channel = IVAL(channel_type,0);
			SAFE_FREE(channel_type);
		} else {
			*channel = get_default_sec_channel();
		}
	}

	return ret;
}
