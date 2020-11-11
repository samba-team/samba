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
#include "libcli/security/security.h"

#include "librpc/gen_ndr/libnet_join.h"
#include "librpc/gen_ndr/ndr_secrets.h"
#include "lib/crypto/crypto.h"
#include "lib/krb5_wrap/krb5_samba.h"
#include "lib/util/time_basic.h"
#include "../libds/common/flags.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

static char *domain_info_keystr(const char *domain);

static char *des_salt_key(const char *realm);

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

static const char *domain_guid_keystr(const char *domain)
{
	char *keystr;

	keystr = talloc_asprintf_strupper_m(talloc_tos(), "%s/%s",
					    SECRETS_DOMAIN_GUID, domain);
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
		ret = secrets_delete_entry(protect_ids_keystr(domain));
		if (!ret) {
			DEBUG(0, ("Failed to remove Domain IDs protection\n"));
		}
		return ret;
	}
	return true;
}

bool secrets_store_domain_sid(const char *domain, const struct dom_sid  *sid)
{
	char *protect_ids;
	bool ret;
	struct dom_sid clean_sid = { 0 };

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

	/*
	 * use a copy to prevent uninitialized memory from being carried over
	 * to the tdb
	 */
	sid_copy(&clean_sid, sid);

	ret = secrets_store(domain_sid_keystr(domain),
			    &clean_sid,
			    sizeof(struct dom_sid));

	/* Force a re-query, in the case where we modified our domain */
	if (ret) {
		if (dom_sid_equal(get_global_sam_sid(), sid) == false) {
			reset_global_sam_sid();
		}
	}
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

bool secrets_store_domain_guid(const char *domain, const struct GUID *guid)
{
	char *protect_ids;
	const char *key;

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

	key = domain_guid_keystr(domain);
	return secrets_store(key, guid, sizeof(struct GUID));
}

bool secrets_fetch_domain_guid(const char *domain, struct GUID *guid)
{
	struct GUID *dyn_guid;
	const char *key;
	size_t size = 0;
	struct GUID new_guid;

	key = domain_guid_keystr(domain);
	dyn_guid = (struct GUID *)secrets_fetch(key, &size);

	if (!dyn_guid) {
		if (lp_server_role() == ROLE_DOMAIN_PDC ||
		    lp_server_role() == ROLE_IPA_DC) {
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
 Routine to get the default secure channel type for trust accounts
************************************************************************/

enum netr_SchannelType get_default_sec_channel(void)
{
	if (IS_DC) {
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
 Routine to delete all information related to the domain joined machine.
************************************************************************/

bool secrets_delete_machine_password_ex(const char *domain, const char *realm)
{
	const char *tmpkey = NULL;
	bool ok;

	tmpkey = domain_info_keystr(domain);
	ok = secrets_delete(tmpkey);
	if (!ok) {
		return false;
	}

	if (realm != NULL) {
		tmpkey = des_salt_key(domain);
		ok = secrets_delete(tmpkey);
		if (!ok) {
			return false;
		}
	}

	tmpkey = domain_guid_keystr(domain);
	ok = secrets_delete(tmpkey);
	if (!ok) {
		return false;
	}

	tmpkey = machine_prev_password_keystr(domain);
	ok = secrets_delete(tmpkey);
	if (!ok) {
		return false;
	}

	tmpkey = machine_password_keystr(domain);
	ok = secrets_delete(tmpkey);
	if (!ok) {
		return false;
	}

	tmpkey = machine_sec_channel_type_keystr(domain);
	ok = secrets_delete(tmpkey);
	if (!ok) {
		return false;
	}

	tmpkey = machine_last_change_time_keystr(domain);
	ok = secrets_delete(tmpkey);
	if (!ok) {
		return false;
	}

	tmpkey = domain_sid_keystr(domain);
	ok = secrets_delete(tmpkey);
	if (!ok) {
		return false;
	}

	return true;
}

/************************************************************************
 Routine to delete the domain sid
************************************************************************/

bool secrets_delete_domain_sid(const char *domain)
{
	return secrets_delete_entry(domain_sid_keystr(domain));
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
				   uint32_t secure_channel_type,
				   bool delete_join)
{
	bool ret;
	uint8_t last_change_time_store[4];
	TALLOC_CTX *frame = talloc_stackframe();
	uint8_t sec_channel_bytes[4];

	if (delete_join) {
		secrets_delete_machine_password_ex(domain, realm);
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
		ret = secrets_delete(machine_prev_password_keystr(domain));
	}
	if (!ret) {
		TALLOC_FREE(frame);
		return ret;
	}

	if (secure_channel_type == 0) {
		/* We delete this and instead have the read code fall back to
		 * a default based on server role, as our caller can't specify
		 * this with any more certainty */
		ret = secrets_delete(machine_sec_channel_type_keystr(domain));
		if (!ret) {
			TALLOC_FREE(frame);
			return ret;
		}
	} else {
		SIVAL(&sec_channel_bytes, 0, secure_channel_type);
		ret = secrets_store(machine_sec_channel_type_keystr(domain), 
				    &sec_channel_bytes, sizeof(sec_channel_bytes));
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

	if (realm != NULL) {
		char *key = des_salt_key(realm);

		if (salting_principal != NULL) {
			ret = secrets_store(key,
					    salting_principal,
					    strlen(salting_principal)+1);
		} else {
			ret = secrets_delete(key);
		}
	}

	TALLOC_FREE(frame);
	return ret;
}

/************************************************************************
 Return the standard DES salt key
************************************************************************/

char* kerberos_standard_des_salt( void )
{
	fstring salt;

	fstr_sprintf( salt, "host/%s.%s@", lp_netbios_name(), lp_realm() );
	(void)strlower_m( salt );
	fstrcat( salt, lp_realm() );

	return SMB_STRDUP( salt );
}

/************************************************************************
************************************************************************/

static char *des_salt_key(const char *realm)
{
	char *keystr;

	keystr = talloc_asprintf_strupper_m(talloc_tos(), "%s/DES/%s",
					    SECRETS_SALTING_PRINCIPAL,
					    realm);
	SMB_ASSERT(keystr != NULL);
	return keystr;
}

/************************************************************************
************************************************************************/

bool kerberos_secrets_store_des_salt( const char* salt )
{
	char* key;
	bool ret;

	key = des_salt_key(lp_realm());
	if (key == NULL) {
		DEBUG(0,("kerberos_secrets_store_des_salt: failed to generate key!\n"));
		return False;
	}

	if ( !salt ) {
		DEBUG(8,("kerberos_secrets_store_des_salt: deleting salt\n"));
		secrets_delete_entry( key );
		return True;
	}

	DEBUG(3,("kerberos_secrets_store_des_salt: Storing salt \"%s\"\n", salt));

	ret = secrets_store( key, salt, strlen(salt)+1 );

	TALLOC_FREE(key);

	return ret;
}

/************************************************************************
************************************************************************/

static
char* kerberos_secrets_fetch_des_salt( void )
{
	char *salt, *key;

	key = des_salt_key(lp_realm());
	if (key == NULL) {
		DEBUG(0,("kerberos_secrets_fetch_des_salt: failed to generate key!\n"));
		return NULL;
	}

	salt = (char*)secrets_fetch( key, NULL );

	TALLOC_FREE(key);

	return salt;
}

/************************************************************************
 Routine to get the salting principal for this service.
 Caller must free if return is not null.
 ************************************************************************/

char *kerberos_secrets_fetch_salt_princ(void)
{
	char *salt_princ_s;
	/* lookup new key first */

	salt_princ_s = kerberos_secrets_fetch_des_salt();
	if (salt_princ_s == NULL) {
		/* fall back to host/machine.realm@REALM */
		salt_princ_s = kerberos_standard_des_salt();
	}

	return salt_princ_s;
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
 Routine to fetch the last change time of the machine account password
  for a realm
************************************************************************/

time_t secrets_fetch_pass_last_set_time(const char *domain)
{
	uint32_t *last_set_time;
	time_t pass_last_set_time;

	last_set_time = secrets_fetch(machine_last_change_time_keystr(domain),
				      NULL);
	if (last_set_time) {
		pass_last_set_time = IVAL(last_set_time,0);
		SAFE_FREE(last_set_time);
	} else {
		pass_last_set_time = 0;
	}

	return pass_last_set_time;
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
		*pass_last_set_time = secrets_fetch_pass_last_set_time(domain);
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

static char *domain_info_keystr(const char *domain)
{
	char *keystr;

	keystr = talloc_asprintf_strupper_m(talloc_tos(), "%s/%s",
					    SECRETS_MACHINE_DOMAIN_INFO,
					    domain);
	SMB_ASSERT(keystr != NULL);
	return keystr;
}

/************************************************************************
 Routine to get account password to trusted domain
************************************************************************/

static NTSTATUS secrets_fetch_domain_info1_by_key(const char *key,
				TALLOC_CTX *mem_ctx,
				struct secrets_domain_info1 **_info1)
{
	struct secrets_domain_infoB sdib = { .version = 0, };
	enum ndr_err_code ndr_err;
	/* unpacking structures */
	DATA_BLOB blob;

	/* fetching trusted domain password structure */
	blob.data = (uint8_t *)secrets_fetch(key, &blob.length);
	if (blob.data == NULL) {
		DBG_NOTICE("secrets_fetch failed!\n");
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* unpack trusted domain password */
	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &sdib,
			(ndr_pull_flags_fn_t)ndr_pull_secrets_domain_infoB);
	SAFE_FREE(blob.data);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("ndr_pull_struct_blob failed - %s!\n",
			ndr_errstr(ndr_err));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (sdib.version != SECRETS_DOMAIN_INFO_VERSION_1) {
		DBG_ERR("sdib.version = %u\n", (unsigned)sdib.version);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	*_info1 = sdib.info.info1;
	return NT_STATUS_OK;;
}

static NTSTATUS secrets_fetch_domain_info(const char *domain,
					  TALLOC_CTX *mem_ctx,
					  struct secrets_domain_info1 **pinfo)
{
	char *key = domain_info_keystr(domain);
	return secrets_fetch_domain_info1_by_key(key, mem_ctx, pinfo);
}

void secrets_debug_domain_info(int lvl, const struct secrets_domain_info1 *info1,
			       const char *name)
{
	struct secrets_domain_infoB sdib = {
		.version = SECRETS_DOMAIN_INFO_VERSION_1,
	};

	sdib.info.info1 = discard_const_p(struct secrets_domain_info1, info1);

	ndr_print_debug((ndr_print_fn_t)ndr_print_secrets_domain_infoB,
			name, &sdib);
}

char *secrets_domain_info_string(TALLOC_CTX *mem_ctx, const struct secrets_domain_info1 *info1,
				 const char *name, bool include_secrets)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct secrets_domain_infoB sdib = {
		.version = SECRETS_DOMAIN_INFO_VERSION_1,
	};
	struct ndr_print *ndr = NULL;
	char *ret = NULL;

	sdib.info.info1 = discard_const_p(struct secrets_domain_info1, info1);

	ndr = talloc_zero(frame, struct ndr_print);
	if (ndr == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}
	ndr->private_data = talloc_strdup(ndr, "");
	if (ndr->private_data == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}
	ndr->print = ndr_print_string_helper;
	ndr->depth = 1;
	ndr->print_secrets = include_secrets;

	ndr_print_secrets_domain_infoB(ndr, name, &sdib);
	ret = talloc_steal(mem_ctx, (char *)ndr->private_data);
	TALLOC_FREE(frame);
	return ret;
}

static NTSTATUS secrets_store_domain_info1_by_key(const char *key,
					const struct secrets_domain_info1 *info1)
{
	struct secrets_domain_infoB sdib = {
		.version = SECRETS_DOMAIN_INFO_VERSION_1,
	};
	/* packing structures */
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	bool ok;

	sdib.info.info1 = discard_const_p(struct secrets_domain_info1, info1);

	ndr_err = ndr_push_struct_blob(&blob, talloc_tos(), &sdib,
			(ndr_push_flags_fn_t)ndr_push_secrets_domain_infoB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	ok = secrets_store(key, blob.data, blob.length);
	data_blob_clear_free(&blob);
	if (!ok) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	return NT_STATUS_OK;
}

static NTSTATUS secrets_store_domain_info(const struct secrets_domain_info1 *info,
					  bool upgrade)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *domain = info->domain_info.name.string;
	const char *realm = info->domain_info.dns_domain.string;
	char *key = domain_info_keystr(domain);
	struct db_context *db = NULL;
	struct timeval last_change_tv;
	const DATA_BLOB *cleartext_blob = NULL;
	DATA_BLOB pw_blob = data_blob_null;
	DATA_BLOB old_pw_blob = data_blob_null;
	const char *pw = NULL;
	const char *old_pw = NULL;
	bool ok;
	NTSTATUS status;
	int ret;
	int role = lp_server_role();

	switch (info->secure_channel_type) {
	case SEC_CHAN_WKSTA:
	case SEC_CHAN_BDC:
		if (!upgrade && role >= ROLE_ACTIVE_DIRECTORY_DC) {
			DBG_ERR("AD_DC not supported for %s\n",
				domain);
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_ERROR;
		}

		break;
	default:
		DBG_ERR("SEC_CHAN_* not supported for %s\n",
			domain);
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	db = secrets_db_ctx();

	ret = dbwrap_transaction_start(db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_start() failed for %s\n",
			domain);
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	ok = secrets_clear_domain_protection(domain);
	if (!ok) {
		DBG_ERR("secrets_clear_domain_protection(%s) failed\n",
			domain);
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	ok = secrets_delete_machine_password_ex(domain, realm);
	if (!ok) {
		DBG_ERR("secrets_delete_machine_password_ex(%s) failed\n",
			domain);
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	status = secrets_store_domain_info1_by_key(key, info);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_store_domain_info1_by_key() failed "
			"for %s - %s\n", domain, nt_errstr(status));
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return status;
	}

	/*
	 * We use info->password_last_change instead
	 * of info->password.change_time because
	 * we may want to defer the next change approach
	 * if the server rejected the change the last time,
	 * e.g. due to RefusePasswordChange=1.
	 */
	nttime_to_timeval(&last_change_tv, info->password_last_change);

	cleartext_blob = &info->password->cleartext_blob;
	ok = convert_string_talloc(frame, CH_UTF16MUNGED, CH_UNIX,
				   cleartext_blob->data,
				   cleartext_blob->length,
				   (void **)&pw_blob.data,
				   &pw_blob.length);
	if (!ok) {
		status = NT_STATUS_UNMAPPABLE_CHARACTER;
		if (errno == ENOMEM) {
			status = NT_STATUS_NO_MEMORY;
		}
		DBG_ERR("convert_string_talloc(CH_UTF16MUNGED, CH_UNIX) "
			"failed for pw of %s - %s\n",
			domain, nt_errstr(status));
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return status;
	}
	pw = (const char *)pw_blob.data;
	if (info->old_password != NULL) {
		cleartext_blob = &info->old_password->cleartext_blob;
		ok = convert_string_talloc(frame, CH_UTF16MUNGED, CH_UNIX,
					   cleartext_blob->data,
					   cleartext_blob->length,
					   (void **)&old_pw_blob.data,
					   &old_pw_blob.length);
		if (!ok) {
			status = NT_STATUS_UNMAPPABLE_CHARACTER;
			if (errno == ENOMEM) {
				status = NT_STATUS_NO_MEMORY;
			}
			DBG_ERR("convert_string_talloc(CH_UTF16MUNGED, CH_UNIX) "
				"failed for old_pw of %s - %s\n",
				domain, nt_errstr(status));
			dbwrap_transaction_cancel(db);
			data_blob_clear_free(&pw_blob);
			TALLOC_FREE(frame);
			return status;
		}
		old_pw = (const char *)old_pw_blob.data;
	}

	ok = secrets_store_machine_pw_sync(pw, old_pw,
					   domain, realm,
					   info->salt_principal,
					   info->supported_enc_types,
					   info->domain_info.sid,
					   last_change_tv.tv_sec,
					   info->secure_channel_type,
					   false); /* delete_join */
	data_blob_clear_free(&pw_blob);
	data_blob_clear_free(&old_pw_blob);
	if (!ok) {
		DBG_ERR("secrets_store_machine_pw_sync(%s) failed\n",
			domain);
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	if (!GUID_all_zero(&info->domain_info.domain_guid)) {
		ok = secrets_store_domain_guid(domain,
				&info->domain_info.domain_guid);
		if (!ok) {
			DBG_ERR("secrets_store_domain_guid(%s) failed\n",
				domain);
			dbwrap_transaction_cancel(db);
			TALLOC_FREE(frame);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
	}

	ok = secrets_mark_domain_protected(domain);
	if (!ok) {
		DBG_ERR("secrets_mark_domain_protected(%s) failed\n",
			domain);
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	ret = dbwrap_transaction_commit(db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_commit() failed for %s\n",
			domain);
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static int secrets_domain_info_kerberos_keys(struct secrets_domain_info1_password *p,
					     const char *salt_principal)
{
#ifdef HAVE_ADS
	krb5_error_code krb5_ret;
	krb5_context krb5_ctx = NULL;
	DATA_BLOB cleartext_utf8_b = data_blob_null;
	krb5_data cleartext_utf8;
	krb5_data salt;
	krb5_keyblock key;
	DATA_BLOB aes_256_b = data_blob_null;
	DATA_BLOB aes_128_b = data_blob_null;
	bool ok;
#endif /* HAVE_ADS */
	DATA_BLOB arc4_b = data_blob_null;
	const uint16_t max_keys = 4;
	struct secrets_domain_info1_kerberos_key *keys = NULL;
	uint16_t idx = 0;
	char *salt_data = NULL;

	/*
	 * We calculate:
	 * ENCTYPE_AES256_CTS_HMAC_SHA1_96
	 * ENCTYPE_AES128_CTS_HMAC_SHA1_96
	 * ENCTYPE_ARCFOUR_HMAC
	 * ENCTYPE_DES_CBC_MD5
	 *
	 * We don't include ENCTYPE_DES_CBC_CRC
	 * as W2008R2 also doesn't store it anymore.
	 *
	 * Note we store all enctypes we support,
	 * including the weak encryption types,
	 * but that's no problem as we also
	 * store the cleartext password anyway.
	 *
	 * Which values are then used to construct
	 * a keytab is configured at runtime and the
	 * configuration of msDS-SupportedEncryptionTypes.
	 *
	 * If we don't have kerberos support or no
	 * salt, we only generate an entry for arcfour-hmac-md5.
	 */
	keys = talloc_zero_array(p,
				 struct secrets_domain_info1_kerberos_key,
				 max_keys);
	if (keys == NULL) {
		return ENOMEM;
	}

	arc4_b = data_blob_talloc(keys,
				  p->nt_hash.hash,
				  sizeof(p->nt_hash.hash));
	if (arc4_b.data == NULL) {
		DBG_ERR("data_blob_talloc failed for arcfour-hmac-md5.\n");
		TALLOC_FREE(keys);
		return ENOMEM;
	}

#ifdef HAVE_ADS
	if (salt_principal == NULL) {
		goto no_kerberos;
	}

	krb5_ret = smb_krb5_init_context_common(&krb5_ctx);
	if (krb5_ret != 0) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(krb5_ret));
		TALLOC_FREE(keys);
		return krb5_ret;
	}

	krb5_ret = smb_krb5_salt_principal2data(krb5_ctx, salt_principal,
						p, &salt_data);
	if (krb5_ret != 0) {
		DBG_ERR("smb_krb5_salt_principal2data(%s) failed: %s\n",
			salt_principal,
			smb_get_krb5_error_message(krb5_ctx, krb5_ret, keys));
		krb5_free_context(krb5_ctx);
		TALLOC_FREE(keys);
		return krb5_ret;
	}

	salt = (krb5_data) {
		.data = discard_const(salt_data),
		.length = strlen(salt_data),
	};

	ok = convert_string_talloc(keys, CH_UTF16MUNGED, CH_UTF8,
				   p->cleartext_blob.data,
				   p->cleartext_blob.length,
				   (void **)&cleartext_utf8_b.data,
				   &cleartext_utf8_b.length);
	if (!ok) {
		if (errno != 0) {
			krb5_ret = errno;
		} else {
			krb5_ret = EINVAL;
		}
		krb5_free_context(krb5_ctx);
		TALLOC_FREE(keys);
		return krb5_ret;
	}
	cleartext_utf8.data = (void *)cleartext_utf8_b.data;
	cleartext_utf8.length = cleartext_utf8_b.length;

	krb5_ret = smb_krb5_create_key_from_string(krb5_ctx,
						   NULL,
						   &salt,
						   &cleartext_utf8,
						   ENCTYPE_AES256_CTS_HMAC_SHA1_96,
						   &key);
	if (krb5_ret != 0) {
		DBG_ERR("generation of a aes256-cts-hmac-sha1-96 key failed: %s\n",
			smb_get_krb5_error_message(krb5_ctx, krb5_ret, keys));
		krb5_free_context(krb5_ctx);
		TALLOC_FREE(keys);
		TALLOC_FREE(salt_data);
		return krb5_ret;
	}
	aes_256_b = data_blob_talloc(keys,
				     KRB5_KEY_DATA(&key),
				     KRB5_KEY_LENGTH(&key));
	krb5_free_keyblock_contents(krb5_ctx, &key);
	if (aes_256_b.data == NULL) {
		DBG_ERR("data_blob_talloc failed for aes-256.\n");
		krb5_free_context(krb5_ctx);
		TALLOC_FREE(keys);
		TALLOC_FREE(salt_data);
		return ENOMEM;
	}

	krb5_ret = smb_krb5_create_key_from_string(krb5_ctx,
						   NULL,
						   &salt,
						   &cleartext_utf8,
						   ENCTYPE_AES128_CTS_HMAC_SHA1_96,
						   &key);
	if (krb5_ret != 0) {
		DBG_ERR("generation of a aes128-cts-hmac-sha1-96 key failed: %s\n",
			smb_get_krb5_error_message(krb5_ctx, krb5_ret, keys));
		krb5_free_context(krb5_ctx);
		TALLOC_FREE(keys);
		TALLOC_FREE(salt_data);
		return krb5_ret;
	}
	aes_128_b = data_blob_talloc(keys,
				     KRB5_KEY_DATA(&key),
				     KRB5_KEY_LENGTH(&key));
	krb5_free_keyblock_contents(krb5_ctx, &key);
	if (aes_128_b.data == NULL) {
		DBG_ERR("data_blob_talloc failed for aes-128.\n");
		krb5_free_context(krb5_ctx);
		TALLOC_FREE(keys);
		TALLOC_FREE(salt_data);
		return ENOMEM;
	}

	krb5_free_context(krb5_ctx);
no_kerberos:

	if (aes_256_b.length != 0) {
		keys[idx].keytype		= ENCTYPE_AES256_CTS_HMAC_SHA1_96;
		keys[idx].iteration_count	= 4096;
		keys[idx].value			= aes_256_b;
		idx += 1;
	}

	if (aes_128_b.length != 0) {
		keys[idx].keytype		= ENCTYPE_AES128_CTS_HMAC_SHA1_96;
		keys[idx].iteration_count	= 4096;
		keys[idx].value			= aes_128_b;
		idx += 1;
	}

#endif /* HAVE_ADS */

	keys[idx].keytype		= ENCTYPE_ARCFOUR_HMAC;
	keys[idx].iteration_count	= 4096;
	keys[idx].value			= arc4_b;
	idx += 1;

	p->salt_data = salt_data;
	p->default_iteration_count = 4096;
	p->num_keys = idx;
	p->keys = keys;
	return 0;
}

static NTSTATUS secrets_domain_info_password_create(TALLOC_CTX *mem_ctx,
				const char *cleartext_unix,
				const char *salt_principal,
				NTTIME change_time,
				const char *change_server,
				struct secrets_domain_info1_password **_p)
{
	struct secrets_domain_info1_password *p = NULL;
	bool ok;
	size_t len;
	int ret;

	if (change_server == NULL) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	p = talloc_zero(mem_ctx, struct secrets_domain_info1_password);
	if (p == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	p->change_time = change_time;
	p->change_server = talloc_strdup(p, change_server);
	if (p->change_server == NULL) {
		TALLOC_FREE(p);
		return NT_STATUS_NO_MEMORY;
	}
	len = strlen(cleartext_unix);
	ok = convert_string_talloc(p, CH_UNIX, CH_UTF16,
				   cleartext_unix, len,
				   (void **)&p->cleartext_blob.data,
				   &p->cleartext_blob.length);
	if (!ok) {
		NTSTATUS status = NT_STATUS_UNMAPPABLE_CHARACTER;
		if (errno == ENOMEM) {
			status = NT_STATUS_NO_MEMORY;
		}
		TALLOC_FREE(p);
		return status;
	}
	mdfour(p->nt_hash.hash,
	       p->cleartext_blob.data,
	       p->cleartext_blob.length);

	ret = secrets_domain_info_kerberos_keys(p, salt_principal);
	if (ret != 0) {
		NTSTATUS status = krb5_to_nt_status(ret);
		TALLOC_FREE(p);
		return status;
	}

	*_p = p;
	return NT_STATUS_OK;
}

NTSTATUS secrets_fetch_or_upgrade_domain_info(const char *domain,
					TALLOC_CTX *mem_ctx,
					struct secrets_domain_info1 **pinfo)
{
	TALLOC_CTX *frame = NULL;
	struct secrets_domain_info1 *old = NULL;
	struct secrets_domain_info1 *info = NULL;
	const char *dns_domain = NULL;
	const char *server = NULL;
	struct db_context *db = NULL;
	time_t last_set_time;
	NTTIME last_set_nt;
	enum netr_SchannelType channel;
	char *pw = NULL;
	char *old_pw = NULL;
	struct dom_sid domain_sid;
	struct GUID domain_guid;
	bool ok;
	NTSTATUS status;
	int ret;

	ok = strequal(domain, lp_workgroup());
	if (ok) {
		dns_domain = lp_dnsdomain();

		if (dns_domain != NULL && dns_domain[0] == '\0') {
			dns_domain = NULL;
		}
	}

	last_set_time = secrets_fetch_pass_last_set_time(domain);
	if (last_set_time == 0) {
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}
	unix_to_nt_time(&last_set_nt, last_set_time);

	frame = talloc_stackframe();

	status = secrets_fetch_domain_info(domain, frame, &old);
	if (NT_STATUS_IS_OK(status)) {
		if (old->password_last_change >= last_set_nt) {
			*pinfo = talloc_move(mem_ctx, &old);
			TALLOC_FREE(frame);
			return NT_STATUS_OK;
		}
		TALLOC_FREE(old);
	}

	info = talloc_zero(frame, struct secrets_domain_info1);
	if (info == NULL) {
		DBG_ERR("talloc_zero failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	db = secrets_db_ctx();

	ret = dbwrap_transaction_start(db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_start() failed for %s\n",
			domain);
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	pw = secrets_fetch_machine_password(domain,
					    &last_set_time,
					    &channel);
	if (pw == NULL) {
		DBG_ERR("secrets_fetch_machine_password(%s) failed\n",
			domain);
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}
	unix_to_nt_time(&last_set_nt, last_set_time);

	old_pw = secrets_fetch_prev_machine_password(domain);

	ok = secrets_fetch_domain_sid(domain, &domain_sid);
	if (!ok) {
		DBG_ERR("secrets_fetch_domain_sid(%s) failed\n",
			domain);
		dbwrap_transaction_cancel(db);
		SAFE_FREE(old_pw);
		SAFE_FREE(pw);
		TALLOC_FREE(frame);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	ok = secrets_fetch_domain_guid(domain, &domain_guid);
	if (!ok) {
		domain_guid = GUID_zero();
	}

	info->computer_name = lp_netbios_name();
	info->account_name = talloc_asprintf(frame, "%s$", info->computer_name);
	if (info->account_name == NULL) {
		DBG_ERR("talloc_asprintf(%s$) failed\n", info->computer_name);
		dbwrap_transaction_cancel(db);
		SAFE_FREE(old_pw);
		SAFE_FREE(pw);
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	info->secure_channel_type = channel;

	info->domain_info.name.string = domain;
	info->domain_info.dns_domain.string = dns_domain;
	info->domain_info.dns_forest.string = dns_domain;
	info->domain_info.domain_guid = domain_guid;
	info->domain_info.sid = &domain_sid;

	info->trust_flags = NETR_TRUST_FLAG_PRIMARY;
	info->trust_flags |= NETR_TRUST_FLAG_OUTBOUND;

	if (dns_domain != NULL) {
		/*
		 * We just assume all AD domains are
		 * NETR_TRUST_FLAG_NATIVE these days.
		 *
		 * This isn't used anyway for now.
		 */
		info->trust_flags |= NETR_TRUST_FLAG_NATIVE;

		info->trust_type = LSA_TRUST_TYPE_UPLEVEL;

		server = info->domain_info.dns_domain.string;
	} else {
		info->trust_type = LSA_TRUST_TYPE_DOWNLEVEL;

		server = talloc_asprintf(info,
					 "%s#%02X",
					 domain,
					 NBT_NAME_PDC);
		if (server == NULL) {
			DBG_ERR("talloc_asprintf(%s#%02X) failed\n",
				domain, NBT_NAME_PDC);
			dbwrap_transaction_cancel(db);
			SAFE_FREE(pw);
			SAFE_FREE(old_pw);
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}
	info->trust_attributes = LSA_TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL;

	info->join_time = 0;

	/*
	 * We don't have enough information about the configured
	 * enctypes.
	 */
	info->supported_enc_types = 0;
	info->salt_principal = NULL;
	if (info->trust_type == LSA_TRUST_TYPE_UPLEVEL) {
		char *p = NULL;

		p = kerberos_secrets_fetch_salt_princ();
		if (p == NULL) {
			dbwrap_transaction_cancel(db);
			SAFE_FREE(old_pw);
			SAFE_FREE(pw);
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_ERROR;
		}
		info->salt_principal = talloc_strdup(info, p);
		SAFE_FREE(p);
		if (info->salt_principal == NULL) {
			dbwrap_transaction_cancel(db);
			SAFE_FREE(pw);
			SAFE_FREE(old_pw);
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	info->password_last_change = last_set_nt;
	info->password_changes = 1;
	info->next_change = NULL;

	status = secrets_domain_info_password_create(info,
						     pw,
						     info->salt_principal,
						     last_set_nt, server,
						     &info->password);
	SAFE_FREE(pw);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_domain_info_password_create(pw) failed "
			"for %s - %s\n", domain, nt_errstr(status));
		dbwrap_transaction_cancel(db);
		SAFE_FREE(old_pw);
		TALLOC_FREE(frame);
		return status;
	}

	/*
	 * After a join we don't have old passwords.
	 */
	if (old_pw != NULL) {
		status = secrets_domain_info_password_create(info,
							     old_pw,
							     info->salt_principal,
							     0, server,
							     &info->old_password);
		SAFE_FREE(old_pw);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("secrets_domain_info_password_create(old) failed "
				"for %s - %s\n", domain, nt_errstr(status));
			dbwrap_transaction_cancel(db);
			TALLOC_FREE(frame);
			return status;
		}
		info->password_changes += 1;
	} else {
		info->old_password = NULL;
	}
	info->older_password = NULL;

	secrets_debug_domain_info(DBGLVL_INFO, info, "upgrade");

	status = secrets_store_domain_info(info, true /* upgrade */);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_store_domain_info() failed "
			"for %s - %s\n", domain, nt_errstr(status));
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return status;
	}

	/*
	 * We now reparse it.
	 */
	status = secrets_fetch_domain_info(domain, frame, &info);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_fetch_domain_info() failed "
			"for %s - %s\n", domain, nt_errstr(status));
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return status;
	}

	ret = dbwrap_transaction_commit(db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_commit() failed for %s\n",
			domain);
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	*pinfo = talloc_move(mem_ctx, &info);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

NTSTATUS secrets_store_JoinCtx(const struct libnet_JoinCtx *r)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct secrets_domain_info1 *old = NULL;
	struct secrets_domain_info1 *info = NULL;
	struct db_context *db = NULL;
	struct timeval tv = timeval_current();
	NTTIME now = timeval_to_nttime(&tv);
	const char *domain = r->out.netbios_domain_name;
	NTSTATUS status;
	int ret;

	info = talloc_zero(frame, struct secrets_domain_info1);
	if (info == NULL) {
		DBG_ERR("talloc_zero failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	info->computer_name = r->in.machine_name;
	info->account_name = r->out.account_name;
	info->secure_channel_type = r->in.secure_channel_type;

	info->domain_info.name.string =
		r->out.netbios_domain_name;
	info->domain_info.dns_domain.string =
		r->out.dns_domain_name;
	info->domain_info.dns_forest.string =
		r->out.forest_name;
	info->domain_info.domain_guid = r->out.domain_guid;
	info->domain_info.sid = r->out.domain_sid;

	info->trust_flags = NETR_TRUST_FLAG_PRIMARY;
	info->trust_flags |= NETR_TRUST_FLAG_OUTBOUND;
	if (r->out.domain_is_ad) {
		/*
		 * We just assume all AD domains are
		 * NETR_TRUST_FLAG_NATIVE these days.
		 *
		 * This isn't used anyway for now.
		 */
		info->trust_flags |= NETR_TRUST_FLAG_NATIVE;

		info->trust_type = LSA_TRUST_TYPE_UPLEVEL;
	} else {
		info->trust_type = LSA_TRUST_TYPE_DOWNLEVEL;
	}
	info->trust_attributes = LSA_TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL;

	info->join_time = now;

	info->supported_enc_types = r->out.set_encryption_types;
	info->salt_principal = r->out.krb5_salt;

	if (info->salt_principal == NULL && r->out.domain_is_ad) {
		char *p = NULL;

		ret = smb_krb5_salt_principal_str(info->domain_info.dns_domain.string,
						  info->account_name,
						  NULL /* userPrincipalName */,
						  UF_WORKSTATION_TRUST_ACCOUNT,
						  info, &p);
		if (ret != 0) {
			status = krb5_to_nt_status(ret);
			DBG_ERR("smb_krb5_salt_principal() failed "
				"for %s - %s\n", domain, nt_errstr(status));
			TALLOC_FREE(frame);
			return status;
		}
		info->salt_principal = p;
	}

	info->password_last_change = now;
	info->password_changes = 1;
	info->next_change = NULL;

	status = secrets_domain_info_password_create(info,
						     r->in.machine_password,
						     info->salt_principal,
						     now, r->in.dc_name,
						     &info->password);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_domain_info_password_create(pw) failed "
			"for %s - %s\n", domain, nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	db = secrets_db_ctx();

	ret = dbwrap_transaction_start(db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_start() failed for %s\n",
			domain);
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	status = secrets_fetch_or_upgrade_domain_info(domain, frame, &old);
	if (NT_STATUS_EQUAL(status, NT_STATUS_CANT_ACCESS_DOMAIN_INFO)) {
		DBG_DEBUG("no old join for domain(%s) available\n",
			  domain);
		old = NULL;
	} else if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_fetch_or_upgrade_domain_info(%s) failed\n",
			domain);
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return status;
	}

	/*
	 * We reuse values from an old join, so that
	 * we still accept already granted kerberos tickets.
	 */
	if (old != NULL) {
		info->old_password = old->password;
		info->older_password = old->old_password;
	}

	secrets_debug_domain_info(DBGLVL_INFO, info, "join");

	status = secrets_store_domain_info(info, false /* upgrade */);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_store_domain_info() failed "
			"for %s - %s\n", domain, nt_errstr(status));
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return status;
	}

	ret = dbwrap_transaction_commit(db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_commit() failed for %s\n",
			domain);
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

NTSTATUS secrets_prepare_password_change(const char *domain, const char *dcname,
					 const char *cleartext_unix,
					 TALLOC_CTX *mem_ctx,
					 struct secrets_domain_info1 **pinfo,
					 struct secrets_domain_info1_change **pprev)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct db_context *db = NULL;
	struct secrets_domain_info1 *info = NULL;
	struct secrets_domain_info1_change *prev = NULL;
	struct secrets_domain_info1_change *next = NULL;
	struct timeval tv = timeval_current();
	NTTIME now = timeval_to_nttime(&tv);
	NTSTATUS status;
	int ret;

	db = secrets_db_ctx();

	ret = dbwrap_transaction_start(db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_start() failed for %s\n",
			domain);
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	status = secrets_fetch_or_upgrade_domain_info(domain, frame, &info);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_fetch_or_upgrade_domain_info(%s) failed\n",
			domain);
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return status;
	}

	prev = info->next_change;
	info->next_change = NULL;

	next = talloc_zero(frame, struct secrets_domain_info1_change);
	if (next == NULL) {
		DBG_ERR("talloc_zero failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	if (prev != NULL) {
		*next = *prev;
	} else {
		status = secrets_domain_info_password_create(next,
							     cleartext_unix,
							     info->salt_principal,
							     now, dcname,
							     &next->password);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("secrets_domain_info_password_create(next) failed "
				"for %s - %s\n", domain, nt_errstr(status));
			dbwrap_transaction_cancel(db);
			TALLOC_FREE(frame);
			return status;
		}
	}

	next->local_status = NT_STATUS_OK;
	next->remote_status = NT_STATUS_NOT_COMMITTED;
	next->change_time = now;
	next->change_server = dcname;

	info->next_change = next;

	secrets_debug_domain_info(DBGLVL_INFO, info, "prepare_change");

	status = secrets_store_domain_info(info, false /* upgrade */);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_store_domain_info() failed "
			"for %s - %s\n", domain, nt_errstr(status));
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return status;
	}

	/*
	 * We now reparse it.
	 */
	status = secrets_fetch_domain_info(domain, frame, &info);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_fetch_domain_info(%s) failed\n", domain);
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return status;
	}

	ret = dbwrap_transaction_commit(db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_commit() failed for %s\n",
			domain);
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	*pinfo = talloc_move(mem_ctx, &info);
	if (prev != NULL) {
		*pprev = talloc_move(mem_ctx, &prev);
	} else {
		*pprev = NULL;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static NTSTATUS secrets_check_password_change(const struct secrets_domain_info1 *cookie,
					      TALLOC_CTX *mem_ctx,
					      struct secrets_domain_info1 **pstored)
{
	const char *domain = cookie->domain_info.name.string;
	struct secrets_domain_info1 *stored = NULL;
	struct secrets_domain_info1_change *sn = NULL;
	struct secrets_domain_info1_change *cn = NULL;
	NTSTATUS status;
	int cmp;

	if (cookie->next_change == NULL) {
		DBG_ERR("cookie->next_change == NULL for %s.\n", domain);
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (cookie->next_change->password == NULL) {
		DBG_ERR("cookie->next_change->password == NULL for %s.\n", domain);
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (cookie->password == NULL) {
		DBG_ERR("cookie->password == NULL for %s.\n", domain);
		return NT_STATUS_INTERNAL_ERROR;
	}

	/*
	 * Here we check that the given strucure still contains the
	 * same secrets_domain_info1_change as currently stored.
	 *
	 * There's always a gap between secrets_prepare_password_change()
	 * and the callers of secrets_check_password_change().
	 */

	status = secrets_fetch_domain_info(domain, mem_ctx, &stored);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_fetch_domain_info(%s) failed\n", domain);
		return status;
	}

	if (stored->next_change == NULL) {
		/*
		 * We hit a race..., the administrator
		 * rejoined or something similar happened.
		 */
		DBG_ERR("stored->next_change == NULL for %s.\n", domain);
		TALLOC_FREE(stored);
		return NT_STATUS_NETWORK_CREDENTIAL_CONFLICT;
	}

	if (stored->password_last_change != cookie->password_last_change) {
		struct timeval store_tv;
		struct timeval_buf store_buf;
		struct timeval cookie_tv;
		struct timeval_buf cookie_buf;

		nttime_to_timeval(&store_tv, stored->password_last_change);
		nttime_to_timeval(&cookie_tv, cookie->password_last_change);

		DBG_ERR("password_last_change differs %s != %s for %s.\n",
			timeval_str_buf(&store_tv, false, false, &store_buf),
			timeval_str_buf(&cookie_tv, false, false, &cookie_buf),
			domain);
		TALLOC_FREE(stored);
		return NT_STATUS_NETWORK_CREDENTIAL_CONFLICT;
	}

	sn = stored->next_change;
	cn = cookie->next_change;

	if (sn->change_time != cn->change_time) {
		struct timeval store_tv;
		struct timeval_buf store_buf;
		struct timeval cookie_tv;
		struct timeval_buf cookie_buf;

		nttime_to_timeval(&store_tv, sn->change_time);
		nttime_to_timeval(&cookie_tv, cn->change_time);

		DBG_ERR("next change_time differs %s != %s for %s.\n",
			timeval_str_buf(&store_tv, false, false, &store_buf),
			timeval_str_buf(&cookie_tv, false, false, &cookie_buf),
			domain);
		TALLOC_FREE(stored);
		return NT_STATUS_NETWORK_CREDENTIAL_CONFLICT;
	}

	if (sn->password->change_time != cn->password->change_time) {
		struct timeval store_tv;
		struct timeval_buf store_buf;
		struct timeval cookie_tv;
		struct timeval_buf cookie_buf;

		nttime_to_timeval(&store_tv, sn->password->change_time);
		nttime_to_timeval(&cookie_tv, cn->password->change_time);

		DBG_ERR("next password.change_time differs %s != %s for %s.\n",
			timeval_str_buf(&store_tv, false, false, &store_buf),
			timeval_str_buf(&cookie_tv, false, false, &cookie_buf),
			domain);
		TALLOC_FREE(stored);
		return NT_STATUS_NETWORK_CREDENTIAL_CONFLICT;
	}

	cmp = memcmp(sn->password->nt_hash.hash,
		     cn->password->nt_hash.hash,
		     16);
	if (cmp != 0) {
		DBG_ERR("next password.nt_hash differs for %s.\n",
			domain);
		TALLOC_FREE(stored);
		return NT_STATUS_NETWORK_CREDENTIAL_CONFLICT;
	}

	cmp = memcmp(stored->password->nt_hash.hash,
		     cookie->password->nt_hash.hash,
		     16);
	if (cmp != 0) {
		DBG_ERR("password.nt_hash differs for %s.\n",
			domain);
		TALLOC_FREE(stored);
		return NT_STATUS_NETWORK_CREDENTIAL_CONFLICT;
	}

	*pstored = stored;
	return NT_STATUS_OK;
}

static NTSTATUS secrets_abort_password_change(const char *change_server,
				NTSTATUS local_status,
				NTSTATUS remote_status,
				const struct secrets_domain_info1 *cookie,
				bool defer)
{
	const char *domain = cookie->domain_info.name.string;
	TALLOC_CTX *frame = talloc_stackframe();
	struct db_context *db = NULL;
	struct secrets_domain_info1 *info = NULL;
	const char *reason = defer ? "defer_change" : "failed_change";
	struct timeval tv = timeval_current();
	NTTIME now = timeval_to_nttime(&tv);
	NTSTATUS status;
	int ret;

	db = secrets_db_ctx();

	ret = dbwrap_transaction_start(db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_start() failed for %s\n",
			domain);
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	/*
	 * secrets_check_password_change()
	 * checks that cookie->next_change
	 * is valid and the same as store
	 * in the database.
	 */
	status = secrets_check_password_change(cookie, frame, &info);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_check_password_change(%s) failed\n", domain);
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return status;
	}

	/*
	 * Remember the last server and error.
	 */
	info->next_change->change_server = change_server;
	info->next_change->change_time = now;
	info->next_change->local_status = local_status;
	info->next_change->remote_status = remote_status;

	/*
	 * Make sure the next automatic change is deferred.
	 */
	if (defer) {
		info->password_last_change = now;
	}

	secrets_debug_domain_info(DBGLVL_WARNING, info, reason);

	status = secrets_store_domain_info(info, false /* upgrade */);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_store_domain_info() failed "
			"for %s - %s\n", domain, nt_errstr(status));
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return status;
	}

	ret = dbwrap_transaction_commit(db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_commit() failed for %s\n",
			domain);
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

NTSTATUS secrets_failed_password_change(const char *change_server,
					NTSTATUS local_status,
					NTSTATUS remote_status,
					const struct secrets_domain_info1 *cookie)
{
	static const bool defer = false;
	return secrets_abort_password_change(change_server,
					     local_status,
					     remote_status,
					     cookie, defer);
}

NTSTATUS secrets_defer_password_change(const char *change_server,
				       NTSTATUS local_status,
				       NTSTATUS remote_status,
				       const struct secrets_domain_info1 *cookie)
{
	static const bool defer = true;
	return secrets_abort_password_change(change_server,
					     local_status,
					     remote_status,
					     cookie, defer);
}

NTSTATUS secrets_finish_password_change(const char *change_server,
					NTTIME change_time,
					const struct secrets_domain_info1 *cookie)
{
	const char *domain = cookie->domain_info.name.string;
	TALLOC_CTX *frame = talloc_stackframe();
	struct db_context *db = NULL;
	struct secrets_domain_info1 *info = NULL;
	struct secrets_domain_info1_change *nc = NULL;
	NTSTATUS status;
	int ret;

	db = secrets_db_ctx();

	ret = dbwrap_transaction_start(db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_start() failed for %s\n",
			domain);
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	/*
	 * secrets_check_password_change() checks that cookie->next_change is
	 * valid and the same as store in the database.
	 */
	status = secrets_check_password_change(cookie, frame, &info);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_check_password_change(%s) failed\n", domain);
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return status;
	}

	nc = info->next_change;

	nc->password->change_server = change_server;
	nc->password->change_time = change_time;

	info->password_last_change = change_time;
	info->password_changes += 1;
	info->next_change = NULL;

	info->older_password = info->old_password;
	info->old_password = info->password;
	info->password = nc->password;

	secrets_debug_domain_info(DBGLVL_WARNING, info, "finish_change");

	status = secrets_store_domain_info(info, false /* upgrade */);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_store_domain_info() failed "
			"for %s - %s\n", domain, nt_errstr(status));
		dbwrap_transaction_cancel(db);
		TALLOC_FREE(frame);
		return status;
	}

	ret = dbwrap_transaction_commit(db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_commit() failed for %s\n",
			domain);
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}
