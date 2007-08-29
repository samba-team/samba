/* 
   ldb database module

   Copyright (C) Simo Sorce  2004-2006
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2006
   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Stefan Metzmacher 2007

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

/*
 *  Name: ldb
 *
 *  Component: ldb password_hash module
 *
 *  Description: correctly update hash values based on changes to sambaPassword and friends
 *
 *  Author: Andrew Bartlett
 *  Author: Stefan Metzmacher
 */

#include "includes.h"
#include "libcli/ldap/ldap.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "librpc/gen_ndr/misc.h"
#include "librpc/gen_ndr/samr.h"
#include "libcli/auth/libcli_auth.h"
#include "libcli/security/security.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "system/time.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/flags.h"
#include "dsdb/samdb/ldb_modules/password_modules.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "lib/crypto/crypto.h"

/* If we have decided there is reason to work on this request, then
 * setup all the password hash types correctly.
 *
 * If the administrator doesn't want the sambaPassword stored (set in the
 * domain and per-account policies) then we must strip that out before
 * we do the first operation.
 *
 * Once this is done (which could update anything at all), we
 * calculate the password hashes.
 *
 * This function must not only update the unicodePwd, dBCSPwd and
 * supplementalCredentials fields, it must also atomicly increment the
 * msDS-KeyVersionNumber.  We should be in a transaction, so all this
 * should be quite safe...
 *
 * Finally, if the administrator has requested that a password history
 * be maintained, then this should also be written out.
 *
 */

struct ph_context {

	enum ph_type {PH_ADD, PH_MOD} type;
	enum ph_step {PH_ADD_SEARCH_DOM, PH_ADD_DO_ADD, PH_MOD_DO_REQ, PH_MOD_SEARCH_SELF, PH_MOD_SEARCH_DOM, PH_MOD_DO_MOD} step;

	struct ldb_module *module;
	struct ldb_request *orig_req;

	struct ldb_request *dom_req;
	struct ldb_reply *dom_res;

	struct ldb_request *down_req;

	struct ldb_request *search_req;
	struct ldb_reply *search_res;

	struct ldb_request *mod_req;

	struct dom_sid *domain_sid;
};

struct domain_data {
	BOOL store_cleartext;
	uint_t pwdProperties;
	uint_t pwdHistoryLength;
	char *netbios_domain;
	char *dns_domain;
	char *realm;
};

struct setup_password_fields_io {
	struct ph_context *ac;
	struct domain_data *domain;
	struct smb_krb5_context *smb_krb5_context;

	/* infos about the user account */
	struct {
		uint32_t user_account_control;
		const char *sAMAccountName;
		const char *user_principal_name;
		bool is_computer;
	} u;

	/* new credentials */
	struct {
		const char *cleartext;
		struct samr_Password *nt_hash;
		struct samr_Password *lm_hash;
	} n;

	/* old credentials */
	struct {
		uint32_t nt_history_len;
		struct samr_Password *nt_history;
		uint32_t lm_history_len;
		struct samr_Password *lm_history;
		const struct ldb_val *supplemental;
		struct supplementalCredentialsBlob scb;
		uint32_t kvno;
	} o;

	/* generated credentials */
	struct {
		struct samr_Password *nt_hash;
		struct samr_Password *lm_hash;
		uint32_t nt_history_len;
		struct samr_Password *nt_history;
		uint32_t lm_history_len;
		struct samr_Password *lm_history;
		struct ldb_val supplemental;
		NTTIME last_set;
		uint32_t kvno;
	} g;
};

static int setup_nt_fields(struct setup_password_fields_io *io)
{
	uint32_t i;

	io->g.nt_hash = io->n.nt_hash;

	if (io->domain->pwdHistoryLength == 0) {
		return LDB_SUCCESS;
	}

	/* We might not have an old NT password */
	io->g.nt_history = talloc_array(io->ac,
					struct samr_Password,
					io->domain->pwdHistoryLength);
	if (!io->g.nt_history) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	for (i = 0; i < MIN(io->domain->pwdHistoryLength-1, io->o.nt_history_len); i++) {
		io->g.nt_history[i+1] = io->o.nt_history[i];
	}
	io->g.nt_history_len = i + 1;

	if (io->g.nt_hash) {
		io->g.nt_history[0] = *io->g.nt_hash;
	} else {
		/* 
		 * TODO: is this correct?
		 * the simular behavior is correct for the lm history case
		 */
		E_md4hash("", io->g.nt_history[0].hash);
	}

	return LDB_SUCCESS;
}

static int setup_lm_fields(struct setup_password_fields_io *io)
{
	uint32_t i;

	io->g.lm_hash = io->n.lm_hash;

	if (io->domain->pwdHistoryLength == 0) {
		return LDB_SUCCESS;
	}

	/* We might not have an old NT password */
	io->g.lm_history = talloc_array(io->ac,
					struct samr_Password,
					io->domain->pwdHistoryLength);
	if (!io->g.lm_history) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	for (i = 0; i < MIN(io->domain->pwdHistoryLength-1, io->o.lm_history_len); i++) {
		io->g.lm_history[i+1] = io->o.lm_history[i];
	}
	io->g.lm_history_len = i + 1;

	if (io->g.lm_hash) {
		io->g.lm_history[0] = *io->g.lm_hash;
	} else {
		E_deshash("", io->g.lm_history[0].hash);
	}

	return LDB_SUCCESS;
}

static int setup_primary_kerberos(struct setup_password_fields_io *io,
				  const struct supplementalCredentialsBlob *old_scb,
				  struct package_PrimaryKerberosBlob *pkb)
{
	krb5_error_code krb5_ret;
	Principal *salt_principal;
	krb5_salt salt;
	krb5_keyblock key;
	uint32_t k=0;
	struct package_PrimaryKerberosCtr3 *pkb3 = &pkb->ctr.ctr3;
	struct supplementalCredentialsPackage *old_scp = NULL;
	struct package_PrimaryKerberosBlob _old_pkb;
	struct package_PrimaryKerberosCtr3 *old_pkb3 = NULL;
	uint32_t i;
	NTSTATUS status;

	/* Many, many thanks to lukeh@padl.com for this
	 * algorithm, described in his Nov 10 2004 mail to
	 * samba-technical@samba.org */

	/*
	 * Determine a salting principal
	 */
	if (io->u.is_computer) {
		char *name;
		char *saltbody;

		name = talloc_strdup(io->ac, io->u.sAMAccountName);
		if (!name) {
			ldb_oom(io->ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (name[strlen(name)-1] == '$') {
			name[strlen(name)-1] = '\0';
		}

		saltbody = talloc_asprintf(io->ac, "%s.%s", name, io->domain->dns_domain);
		if (!saltbody) {
			ldb_oom(io->ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		krb5_ret = krb5_make_principal(io->smb_krb5_context->krb5_context,
					       &salt_principal,
					       io->domain->realm, "host",
					       saltbody, NULL);
	} else if (io->u.user_principal_name) {
		char *user_principal_name;
		char *p;

		user_principal_name = talloc_strdup(io->ac, io->u.user_principal_name);
		if (!user_principal_name) {
			ldb_oom(io->ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		p = strchr(user_principal_name, '@');
		if (p) {
			p[0] = '\0';
		}

		krb5_ret = krb5_make_principal(io->smb_krb5_context->krb5_context,
					       &salt_principal,
					       io->domain->realm, user_principal_name,
					       NULL);
	} else {
		krb5_ret = krb5_make_principal(io->smb_krb5_context->krb5_context,
					       &salt_principal,
					       io->domain->realm, io->u.sAMAccountName,
					       NULL);
	}
	if (krb5_ret) {
		ldb_asprintf_errstring(io->ac->module->ldb,
				       "setup_primary_kerberos: "
				       "generation of a salting principal failed: %s",
				       smb_get_krb5_error_message(io->smb_krb5_context->krb5_context, krb5_ret, io->ac));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * create salt from salt_principal
	 */
	krb5_ret = krb5_get_pw_salt(io->smb_krb5_context->krb5_context,
				    salt_principal, &salt);
	krb5_free_principal(io->smb_krb5_context->krb5_context, salt_principal);
	if (krb5_ret) {
		ldb_asprintf_errstring(io->ac->module->ldb,
				       "setup_primary_kerberos: "
				       "generation of krb5_salt failed: %s",
				       smb_get_krb5_error_message(io->smb_krb5_context->krb5_context, krb5_ret, io->ac));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	/* create a talloc copy */
	pkb3->salt.string = talloc_strndup(io->ac,
					  salt.saltvalue.data,
					  salt.saltvalue.length);
	krb5_free_salt(io->smb_krb5_context->krb5_context, salt);
	if (!pkb3->salt.string) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	salt.saltvalue.data	= discard_const(pkb3->salt.string);
	salt.saltvalue.length	= strlen(pkb3->salt.string);

	/*
	 * prepare generation of keys
	 *
	 * ENCTYPE_AES256_CTS_HMAC_SHA1_96 (disabled by default)
	 * ENCTYPE_DES_CBC_MD5
	 * ENCTYPE_DES_CBC_CRC
	 *
	 * NOTE: update num_keys when you add another enctype!
	 */
	pkb3->num_keys	= 3;
	pkb3->keys	= talloc_array(io->ac, struct package_PrimaryKerberosKey, pkb3->num_keys);
	if (!pkb3->keys) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	pkb3->unknown3	= talloc_zero_array(io->ac, uint64_t, pkb3->num_keys);
	if (!pkb3->unknown3) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

if (lp_parm_bool(-1, "password_hash", "create_aes_key", false)) {
/*
 * TODO:
 *
 * w2k and w2k3 doesn't support AES, so we'll not include
 * the AES key here yet.
 *
 * Also we don't have an example supplementalCredentials blob
 * from Windows Longhorn Server with AES support
 *
 */
	/*
	 * create ENCTYPE_AES256_CTS_HMAC_SHA1_96 key out of
	 * the salt and the cleartext password
	 */
	krb5_ret = krb5_string_to_key_salt(io->smb_krb5_context->krb5_context,
					   ENCTYPE_AES256_CTS_HMAC_SHA1_96,
					   io->n.cleartext,
					   salt,
					   &key);
	pkb3->keys[k].keytype	= ENCTYPE_AES256_CTS_HMAC_SHA1_96;
	pkb3->keys[k].value	= talloc(pkb3->keys, DATA_BLOB);
	if (!pkb3->keys[k].value) {
		krb5_free_keyblock_contents(io->smb_krb5_context->krb5_context, &key);
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	*pkb3->keys[k].value	= data_blob_talloc(pkb3->keys[k].value,
						   key.keyvalue.data,
						   key.keyvalue.length);
	krb5_free_keyblock_contents(io->smb_krb5_context->krb5_context, &key);
	if (!pkb3->keys[k].value->data) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	k++;
}

	/*
	 * create ENCTYPE_DES_CBC_MD5 key out of
	 * the salt and the cleartext password
	 */
	krb5_ret = krb5_string_to_key_salt(io->smb_krb5_context->krb5_context,
					   ENCTYPE_DES_CBC_MD5,
					   io->n.cleartext,
					   salt,
					   &key);
	pkb3->keys[k].keytype	= ENCTYPE_DES_CBC_MD5;
	pkb3->keys[k].value	= talloc(pkb3->keys, DATA_BLOB);
	if (!pkb3->keys[k].value) {
		krb5_free_keyblock_contents(io->smb_krb5_context->krb5_context, &key);
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	*pkb3->keys[k].value	= data_blob_talloc(pkb3->keys[k].value,
						   key.keyvalue.data,
						   key.keyvalue.length);
	krb5_free_keyblock_contents(io->smb_krb5_context->krb5_context, &key);
	if (!pkb3->keys[k].value->data) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	k++;

	/*
	 * create ENCTYPE_DES_CBC_CRC key out of
	 * the salt and the cleartext password
	 */
	krb5_ret = krb5_string_to_key_salt(io->smb_krb5_context->krb5_context,
					   ENCTYPE_DES_CBC_CRC,
					   io->n.cleartext,
					   salt,
					   &key);
	pkb3->keys[k].keytype	= ENCTYPE_DES_CBC_CRC;
	pkb3->keys[k].value	= talloc(pkb3->keys, DATA_BLOB);
	if (!pkb3->keys[k].value) {
		krb5_free_keyblock_contents(io->smb_krb5_context->krb5_context, &key);
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	*pkb3->keys[k].value	= data_blob_talloc(pkb3->keys[k].value,
						   key.keyvalue.data,
						   key.keyvalue.length);
	krb5_free_keyblock_contents(io->smb_krb5_context->krb5_context, &key);
	if (!pkb3->keys[k].value->data) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	k++;

	/* fix up key number */
	pkb3->num_keys = k;

	/* initialize the old keys to zero */
	pkb3->num_old_keys	= 0;
	pkb3->old_keys		= NULL;
	pkb3->unknown3_old	= NULL;

	/* if there're no old keys, then we're done */
	if (!old_scb) {
		return LDB_SUCCESS;
	}

	for (i=0; i < old_scb->sub.num_packages; i++) {
		if (old_scb->sub.packages[i].unknown1 != 0x00000001) {
			continue;
		}

		if (strcmp("Primary:Kerberos", old_scb->sub.packages[i].name) != 0) {
			continue;
		}

		if (!old_scb->sub.packages[i].data || !old_scb->sub.packages[i].data[0]) {
			continue;
		}

		old_scp = &old_scb->sub.packages[i];
		break;
	}
	/* Primary:Kerberos element of supplementalCredentials */
	if (old_scp) {
		DATA_BLOB blob;

		blob = strhex_to_data_blob(old_scp->data);
		if (!blob.data) {
			ldb_oom(io->ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		talloc_steal(io->ac, blob.data);

		/* TODO: use ndr_pull_struct_blob_all(), when the ndr layer handles it correct with relative pointers */
		status = ndr_pull_struct_blob(&blob, io->ac, &_old_pkb,
					      (ndr_pull_flags_fn_t)ndr_pull_package_PrimaryKerberosBlob);
		if (!NT_STATUS_IS_OK(status)) {
			ldb_asprintf_errstring(io->ac->module->ldb,
					       "setup_primary_kerberos: "
					       "failed to pull old package_PrimaryKerberosBlob: %s",
					       nt_errstr(status));
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (_old_pkb.version != 3) {
			ldb_asprintf_errstring(io->ac->module->ldb,
					       "setup_primary_kerberos: "
					       "package_PrimaryKerberosBlob version[%u] expected[3]",
					       _old_pkb.version);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		old_pkb3 = &_old_pkb.ctr.ctr3;
	}

	/* if we didn't found the old keys we're done */
	if (!old_pkb3) {
		return LDB_SUCCESS;
	}

	/* fill in the old keys */
	pkb3->num_old_keys	= old_pkb3->num_keys;
	pkb3->old_keys		= old_pkb3->keys;
	pkb3->unknown3_old	= old_pkb3->unknown3;

	return LDB_SUCCESS;
}

static int setup_primary_wdigest(struct setup_password_fields_io *io,
				 const struct supplementalCredentialsBlob *old_scb,
				 struct package_PrimaryWDigestBlob *pdb)
{
	DATA_BLOB sAMAccountName;
	DATA_BLOB sAMAccountName_l;
	DATA_BLOB sAMAccountName_u;
	const char *user_principal_name = io->u.user_principal_name;
	DATA_BLOB userPrincipalName;
	DATA_BLOB userPrincipalName_l;
	DATA_BLOB userPrincipalName_u;
	DATA_BLOB netbios_domain;
	DATA_BLOB netbios_domain_l;
	DATA_BLOB netbios_domain_u;
	DATA_BLOB dns_domain;
	DATA_BLOB dns_domain_l;
	DATA_BLOB dns_domain_u;
	DATA_BLOB cleartext;
	DATA_BLOB digest;
	DATA_BLOB delim;
	DATA_BLOB backslash;
	uint8_t i;
	struct {
		DATA_BLOB *user;
		DATA_BLOB *realm;
		DATA_BLOB *nt4dom;
	} wdigest[] = {
	/*
	 * See
	 * http://technet2.microsoft.com/WindowsServer/en/library/717b450c-f4a0-4cc9-86f4-cc0633aae5f91033.mspx?mfr=true
	 * for what precalculated hashes are supposed to be stored...
	 *
	 * I can't reproduce all values which should contain "Digest" as realm,
	 * am I doing something wrong or is w2k3 just broken...?
	 *
	 * W2K3 fills in following for a user:
	 *
	 * dn: CN=NewUser,OU=newtop,DC=sub1,DC=w2k3,DC=vmnet1,DC=vm,DC=base
	 * sAMAccountName: NewUser2Sam
	 * userPrincipalName: NewUser2Princ@sub1.w2k3.vmnet1.vm.base
	 *
	 * 4279815024bda54fc074a5f8bd0a6e6f => NewUser2Sam:SUB1:TestPwd2007
	 * b7ec9da91062199aee7d121e6710fe23 => newuser2sam:sub1:TestPwd2007
	 * 17d290bc5c9f463fac54c37a8cea134d => NEWUSER2SAM:SUB1:TestPwd2007
	 * 4279815024bda54fc074a5f8bd0a6e6f => NewUser2Sam:SUB1:TestPwd2007
	 * 5d57e7823938348127322e08cd81bcb5 => NewUser2Sam:sub1:TestPwd2007
	 * 07dd701bf8a011ece585de3d47237140 => NEWUSER2SAM:sub1:TestPwd2007
	 * e14fb0eb401498d2cb33c9aae1cc7f37 => newuser2sam:SUB1:TestPwd2007
	 * 8dadc90250f873d8b883f79d890bef82 => NewUser2Sam:sub1.w2k3.vmnet1.vm.base:TestPwd2007
	 * f52da1266a6bdd290ffd48b2c823dda7 => newuser2sam:sub1.w2k3.vmnet1.vm.base:TestPwd2007
	 * d2b42f171248cec37a3c5c6b55404062 => NEWUSER2SAM:SUB1.W2K3.VMNET1.VM.BASE:TestPwd2007
	 * fff8d790ff6c152aaeb6ebe17b4021de => NewUser2Sam:SUB1.W2K3.VMNET1.VM.BASE:TestPwd2007
	 * 8dadc90250f873d8b883f79d890bef82 => NewUser2Sam:sub1.w2k3.vmnet1.vm.base:TestPwd2007
	 * 2a7563c3715bc418d626dabef378c008 => NEWUSER2SAM:sub1.w2k3.vmnet1.vm.base:TestPwd2007
	 * c8e9557a87cd4200fda0c11d2fa03f96 => newuser2sam:SUB1.W2K3.VMNET1.VM.BASE:TestPwd2007
	 * 221c55284451ae9b3aacaa2a3c86f10f => NewUser2Princ@sub1.w2k3.vmnet1.vm.base::TestPwd2007
	 * 74e1be668853d4324d38c07e2acfb8ea => (w2k3 has a bug here!) newuser2princ@sub1.w2k3.vmnet1.vm.base::TestPwd2007
	 * e1e244ab7f098e3ae1761be7f9229bbb => NEWUSER2PRINC@SUB1.W2K3.VMNET1.VM.BASE::TestPwd2007
	 * 86db637df42513039920e605499c3af6 => SUB1\NewUser2Sam::TestPwd2007
	 * f5e43474dfaf067fee8197a253debaa2 => sub1\newuser2sam::TestPwd2007
	 * 2ecaa8382e2518e4b77a52422b279467 => SUB1\NEWUSER2SAM::TestPwd2007
	 * 31dc704d3640335b2123d4ee28aa1f11 => ??? changes with NewUser2Sam => NewUser1Sam
	 * 36349f5cecd07320fb3bb0e119230c43 => ??? changes with NewUser2Sam => NewUser1Sam
	 * 12adf019d037fb535c01fd0608e78d9d => ??? changes with NewUser2Sam => NewUser1Sam
	 * 6feecf8e724906f3ee1105819c5105a1 => ??? changes with NewUser2Princ => NewUser1Princ
	 * 6c6911f3de6333422640221b9c51ff1f => ??? changes with NewUser2Princ => NewUser1Princ
	 * 4b279877e742895f9348ac67a8de2f69 => ??? changes with NewUser2Princ => NewUser1Princ
	 * db0c6bff069513e3ebb9870d29b57490 => ??? changes with NewUser2Sam => NewUser1Sam
	 * 45072621e56b1c113a4e04a8ff68cd0e => ??? changes with NewUser2Sam => NewUser1Sam
	 * 11d1220abc44a9c10cf91ef4a9c1de02 => ??? changes with NewUser2Sam => NewUser1Sam
	 *
	 * dn: CN=NewUser,OU=newtop,DC=sub1,DC=w2k3,DC=vmnet1,DC=vm,DC=base
	 * sAMAccountName: NewUser2Sam
	 *
	 * 4279815024bda54fc074a5f8bd0a6e6f => NewUser2Sam:SUB1:TestPwd2007
	 * b7ec9da91062199aee7d121e6710fe23 => newuser2sam:sub1:TestPwd2007
	 * 17d290bc5c9f463fac54c37a8cea134d => NEWUSER2SAM:SUB1:TestPwd2007
	 * 4279815024bda54fc074a5f8bd0a6e6f => NewUser2Sam:SUB1:TestPwd2007
	 * 5d57e7823938348127322e08cd81bcb5 => NewUser2Sam:sub1:TestPwd2007
	 * 07dd701bf8a011ece585de3d47237140 => NEWUSER2SAM:sub1:TestPwd2007
	 * e14fb0eb401498d2cb33c9aae1cc7f37 => newuser2sam:SUB1:TestPwd2007
	 * 8dadc90250f873d8b883f79d890bef82 => NewUser2Sam:sub1.w2k3.vmnet1.vm.base:TestPwd2007
	 * f52da1266a6bdd290ffd48b2c823dda7 => newuser2sam:sub1.w2k3.vmnet1.vm.base:TestPwd2007
	 * d2b42f171248cec37a3c5c6b55404062 => NEWUSER2SAM:SUB1.W2K3.VMNET1.VM.BASE:TestPwd2007
	 * fff8d790ff6c152aaeb6ebe17b4021de => NewUser2Sam:SUB1.W2K3.VMNET1.VM.BASE:TestPwd2007
	 * 8dadc90250f873d8b883f79d890bef82 => NewUser2Sam:sub1.w2k3.vmnet1.vm.base:TestPwd2007
	 * 2a7563c3715bc418d626dabef378c008 => NEWUSER2SAM:sub1.w2k3.vmnet1.vm.base:TestPwd2007
	 * c8e9557a87cd4200fda0c11d2fa03f96 => newuser2sam:SUB1.W2K3.VMNET1.VM.BASE:TestPwd2007
	 * 8a140d30b6f0a5912735dc1e3bc993b4 => NewUser2Sam@sub1.w2k3.vmnet1.vm.base::TestPwd2007
	 * 86d95b2faae6cae4ec261e7fbaccf093 => (here w2k3 is correct) newuser2sam@sub1.w2k3.vmnet1.vm.base::TestPwd2007
	 * dfeff1493110220efcdfc6362e5f5450 => NEWUSER2SAM@SUB1.W2K3.VMNET1.VM.BASE::TestPwd2007
	 * 86db637df42513039920e605499c3af6 => SUB1\NewUser2Sam::TestPwd2007
	 * f5e43474dfaf067fee8197a253debaa2 => sub1\newuser2sam::TestPwd2007
	 * 2ecaa8382e2518e4b77a52422b279467 => SUB1\NEWUSER2SAM::TestPwd2007
	 * 31dc704d3640335b2123d4ee28aa1f11 => ???M1   changes with NewUser2Sam => NewUser1Sam
	 * 36349f5cecd07320fb3bb0e119230c43 => ???M1.L changes with newuser2sam => newuser1sam
	 * 12adf019d037fb535c01fd0608e78d9d => ???M1.U changes with NEWUSER2SAM => NEWUSER1SAM
	 * 569b4533f2d9e580211dd040e5e360a8 => ???M2   changes with NewUser2Princ => NewUser1Princ
	 * 52528bddf310a587c5d7e6a9ae2cbb20 => ???M2.L changes with newuser2princ => newuser1princ
	 * 4f629a4f0361289ca4255ab0f658fcd5 => ???M3 changes with NewUser2Princ => NewUser1Princ (doesn't depend on case of userPrincipal )
	 * db0c6bff069513e3ebb9870d29b57490 => ???M4 changes with NewUser2Sam => NewUser1Sam
	 * 45072621e56b1c113a4e04a8ff68cd0e => ???M5 changes with NewUser2Sam => NewUser1Sam (doesn't depend on case of sAMAccountName)
	 * 11d1220abc44a9c10cf91ef4a9c1de02 => ???M4.U changes with NEWUSER2SAM => NEWUSER1SAM
	 */

	/*
	 * sAMAccountName, netbios_domain
	 */
		{
		.user	= &sAMAccountName,
		.realm	= &netbios_domain,
		},
		{
		.user	= &sAMAccountName_l,
		.realm	= &netbios_domain_l,
		},
		{
		.user	= &sAMAccountName_u,
		.realm	= &netbios_domain_u,
		},
		{
		.user	= &sAMAccountName,
		.realm	= &netbios_domain_u,
		},
		{
		.user	= &sAMAccountName,
		.realm	= &netbios_domain_l,
		},
		{
		.user	= &sAMAccountName_u,
		.realm	= &netbios_domain_l,
		},
		{
		.user	= &sAMAccountName_l,
		.realm	= &netbios_domain_u,
		},
	/* 
	 * sAMAccountName, dns_domain
	 */
		{
		.user	= &sAMAccountName,
		.realm	= &dns_domain,
		},
		{
		.user	= &sAMAccountName_l,
		.realm	= &dns_domain_l,
		},
		{
		.user	= &sAMAccountName_u,
		.realm	= &dns_domain_u,
		},
		{
		.user	= &sAMAccountName,
		.realm	= &dns_domain_u,
		},
		{
		.user	= &sAMAccountName,
		.realm	= &dns_domain_l,
		},
		{
		.user	= &sAMAccountName_u,
		.realm	= &dns_domain_l,
		},
		{
		.user	= &sAMAccountName_l,
		.realm	= &dns_domain_u,
		},
	/* 
	 * userPrincipalName, no realm
	 */
		{
		.user	= &userPrincipalName,
		},
		{
		/* 
		 * NOTE: w2k3 messes this up, if the user has a real userPrincipalName,
		 *       the fallback to the sAMAccountName based userPrincipalName is correct
		 */
		.user	= &userPrincipalName_l,
		},
		{
		.user	= &userPrincipalName_u,
		},
	/* 
	 * nt4dom\sAMAccountName, no realm
	 */
		{
		.user	= &sAMAccountName,
		.nt4dom	= &netbios_domain
		},
		{
		.user	= &sAMAccountName_l,
		.nt4dom	= &netbios_domain_l
		},
		{
		.user	= &sAMAccountName_u,
		.nt4dom	= &netbios_domain_u
		},

	/*
	 * the following ones are guessed depending on the technet2 article
	 * but not reproducable on a w2k3 server
	 */
	/* sAMAccountName with "Digest" realm */
		{
		.user 	= &sAMAccountName,
		.realm	= &digest
		},
		{
		.user 	= &sAMAccountName_l,
		.realm	= &digest
		},
		{
		.user 	= &sAMAccountName_u,
		.realm	= &digest
		},
	/* userPrincipalName with "Digest" realm */
		{
		.user	= &userPrincipalName,
		.realm	= &digest
		},
		{
		.user	= &userPrincipalName_l,
		.realm	= &digest
		},
		{
		.user	= &userPrincipalName_u,
		.realm	= &digest
		},
	/* nt4dom\\sAMAccountName with "Digest" realm */
		{
		.user 	= &sAMAccountName,
		.nt4dom	= &netbios_domain,
		.realm	= &digest
		},
		{
		.user 	= &sAMAccountName_l,
		.nt4dom	= &netbios_domain_l,
		.realm	= &digest
		},
		{
		.user 	= &sAMAccountName_u,
		.nt4dom	= &netbios_domain_u,
		.realm	= &digest
		},
	};

	/* prepare DATA_BLOB's used in the combinations array */
	sAMAccountName		= data_blob_string_const(io->u.sAMAccountName);
	sAMAccountName_l	= data_blob_string_const(strlower_talloc(io->ac, io->u.sAMAccountName));
	if (!sAMAccountName_l.data) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	sAMAccountName_u	= data_blob_string_const(strupper_talloc(io->ac, io->u.sAMAccountName));
	if (!sAMAccountName_u.data) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* if the user doesn't have a userPrincipalName, create one (with lower case realm) */
	if (!user_principal_name) {
		user_principal_name = talloc_asprintf(io->ac, "%s@%s",
						      io->u.sAMAccountName,
						      io->domain->dns_domain);
		if (!user_principal_name) {
			ldb_oom(io->ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}	
	}
	userPrincipalName	= data_blob_string_const(user_principal_name);
	userPrincipalName_l	= data_blob_string_const(strlower_talloc(io->ac, user_principal_name));
	if (!userPrincipalName_l.data) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	userPrincipalName_u	= data_blob_string_const(strupper_talloc(io->ac, user_principal_name));
	if (!userPrincipalName_u.data) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	netbios_domain		= data_blob_string_const(io->domain->netbios_domain);
	netbios_domain_l	= data_blob_string_const(strlower_talloc(io->ac, io->domain->netbios_domain));
	if (!netbios_domain_l.data) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	netbios_domain_u	= data_blob_string_const(strupper_talloc(io->ac, io->domain->netbios_domain));
	if (!netbios_domain_u.data) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	dns_domain		= data_blob_string_const(io->domain->dns_domain);
	dns_domain_l		= data_blob_string_const(io->domain->dns_domain);
	dns_domain_u		= data_blob_string_const(io->domain->realm);

	cleartext		= data_blob_string_const(io->n.cleartext);

	digest			= data_blob_string_const("Digest");

	delim			= data_blob_string_const(":");
	backslash		= data_blob_string_const("\\");

	pdb->num_hashes	= ARRAY_SIZE(wdigest);
	pdb->hashes	= talloc_array(io->ac, struct package_PrimaryWDigestHash, pdb->num_hashes);
	if (!pdb->hashes) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	for (i=0; i < ARRAY_SIZE(wdigest); i++) {
		struct MD5Context md5;
		MD5Init(&md5);
		if (wdigest[i].nt4dom) {
			MD5Update(&md5, wdigest[i].nt4dom->data, wdigest[i].nt4dom->length);
			MD5Update(&md5, backslash.data, backslash.length);
		}
		MD5Update(&md5, wdigest[i].user->data, wdigest[i].user->length);
		MD5Update(&md5, delim.data, delim.length);
		if (wdigest[i].realm) {
			MD5Update(&md5, wdigest[i].realm->data, wdigest[i].realm->length);
		}
		MD5Update(&md5, delim.data, delim.length);
		MD5Update(&md5, cleartext.data, cleartext.length);
		MD5Final(pdb->hashes[i].hash, &md5);
	}

	return LDB_SUCCESS;
}

static int setup_supplemental_field(struct setup_password_fields_io *io)
{
	struct supplementalCredentialsBlob scb;
	struct supplementalCredentialsBlob _old_scb;
	struct supplementalCredentialsBlob *old_scb = NULL;
	/* Packages + (Kerberos, WDigest and maybe CLEARTEXT) */
	uint32_t num_packages = 1 + 2;
	struct supplementalCredentialsPackage packages[1+3];
	struct supplementalCredentialsPackage *pp = &packages[0];
	struct supplementalCredentialsPackage *pk = &packages[1];
	struct supplementalCredentialsPackage *pd = &packages[2];
	struct supplementalCredentialsPackage *pc = NULL;
	struct package_PackagesBlob pb;
	DATA_BLOB pb_blob;
	char *pb_hexstr;
	struct package_PrimaryKerberosBlob pkb;
	DATA_BLOB pkb_blob;
	char *pkb_hexstr;
	struct package_PrimaryWDigestBlob pdb;
	DATA_BLOB pdb_blob;
	char *pdb_hexstr;
	struct package_PrimaryCLEARTEXTBlob pcb;
	DATA_BLOB pcb_blob;
	char *pcb_hexstr;
	int ret;
	NTSTATUS status;
	uint8_t zero16[16];

	ZERO_STRUCT(zero16);

	if (!io->n.cleartext) {
		/* 
		 * when we don't have a cleartext password
		 * we can't setup a supplementalCredential value
		 */
		return LDB_SUCCESS;
	}

	/* if there's an old supplementaCredentials blob then parse it */
	if (io->o.supplemental) {
		status = ndr_pull_struct_blob_all(io->o.supplemental, io->ac, &_old_scb,
						  (ndr_pull_flags_fn_t)ndr_pull_supplementalCredentialsBlob);
		if (!NT_STATUS_IS_OK(status)) {
			ldb_asprintf_errstring(io->ac->module->ldb,
					       "setup_supplemental_field: "
					       "failed to pull old supplementalCredentialsBlob: %s",
					       nt_errstr(status));
			return LDB_ERR_OPERATIONS_ERROR;
		}

		old_scb = &_old_scb;
	}

	if (io->domain->store_cleartext &&
	    (io->u.user_account_control & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED)) {
		pc = &packages[3];
		num_packages++;
	}

	/* Kerberos, WDigest, CLEARTEXT and termination(counted by the Packages element) */
	pb.names = talloc_zero_array(io->ac, const char *, num_packages);

	/*
	 * setup 'Primary:Kerberos' element
	 */
	pb.names[0] = "Kerberos";

	ret = setup_primary_kerberos(io, old_scb, &pkb);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	status = ndr_push_struct_blob(&pkb_blob, io->ac, &pkb,
				      (ndr_push_flags_fn_t)ndr_push_package_PrimaryKerberosBlob);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_asprintf_errstring(io->ac->module->ldb,
				       "setup_supplemental_field: "
				       "failed to push package_PrimaryKerberosBlob: %s",
				       nt_errstr(status));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	/*
	 * TODO:
	 *
	 * This is ugly, but we want to generate the same blob as
	 * w2k and w2k3...we should handle this in the idl
	 */
	if (!data_blob_append(io->ac, &pkb_blob, zero16, sizeof(zero16))) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	pkb_hexstr = data_blob_hex_string(io->ac, &pkb_blob);
	if (!pkb_hexstr) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	pk->name	= "Primary:Kerberos";
	pk->unknown1	= 1;
	pk->data	= pkb_hexstr;

	/*
	 * setup 'Primary:WDigest' element
	 */
	pb.names[1] = "WDigest";

	ret = setup_primary_wdigest(io, old_scb, &pdb);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	status = ndr_push_struct_blob(&pdb_blob, io->ac, &pdb,
				      (ndr_push_flags_fn_t)ndr_push_package_PrimaryWDigestBlob);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_asprintf_errstring(io->ac->module->ldb,
				       "setup_supplemental_field: "
				       "failed to push package_PrimaryWDigestBlob: %s",
				       nt_errstr(status));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	pdb_hexstr = data_blob_hex_string(io->ac, &pdb_blob);
	if (!pdb_hexstr) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	pd->name	= "Primary:WDigest";
	pd->unknown1	= 1;
	pd->data	= pdb_hexstr;

	/*
	 * setup 'Primary:CLEARTEXT' element
	 */
	if (pc) {
		pb.names[2]	= "CLEARTEXT";

		pcb.cleartext	= io->n.cleartext;

		status = ndr_push_struct_blob(&pcb_blob, io->ac, &pcb,
					      (ndr_push_flags_fn_t)ndr_push_package_PrimaryCLEARTEXTBlob);
		if (!NT_STATUS_IS_OK(status)) {
			ldb_asprintf_errstring(io->ac->module->ldb,
					       "setup_supplemental_field: "
					       "failed to push package_PrimaryCLEARTEXTBlob: %s",
					       nt_errstr(status));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		pcb_hexstr = data_blob_hex_string(io->ac, &pcb_blob);
		if (!pcb_hexstr) {
			ldb_oom(io->ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		pc->name	= "Primary:CLEARTEXT";
		pc->unknown1	= 1;
		pc->data	= pcb_hexstr;
	}

	/*
	 * setup 'Packages' element
	 */
	status = ndr_push_struct_blob(&pb_blob, io->ac, &pb,
				      (ndr_push_flags_fn_t)ndr_push_package_PackagesBlob);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_asprintf_errstring(io->ac->module->ldb,
				       "setup_supplemental_field: "
				       "failed to push package_PackagesBlob: %s",
				       nt_errstr(status));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	pb_hexstr = data_blob_hex_string(io->ac, &pb_blob);
	if (!pb_hexstr) {
		ldb_oom(io->ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	pp->name	= "Packages";
	pp->unknown1	= 2;
	pp->data	= pb_hexstr;

	/*
	 * setup 'supplementalCredentials' value
	 */
	scb.sub.num_packages	= num_packages;
	scb.sub.packages	= packages;

	status = ndr_push_struct_blob(&io->g.supplemental, io->ac, &scb,
				      (ndr_push_flags_fn_t)ndr_push_supplementalCredentialsBlob);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_asprintf_errstring(io->ac->module->ldb,
				       "setup_supplemental_field: "
				       "failed to push supplementalCredentialsBlob: %s",
				       nt_errstr(status));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}

static int setup_last_set_field(struct setup_password_fields_io *io)
{
	/* set it as now */
	unix_to_nt_time(&io->g.last_set, time(NULL));

	return LDB_SUCCESS;
}

static int setup_kvno_field(struct setup_password_fields_io *io)
{
	/* increment by one */
	io->g.kvno = io->o.kvno + 1;

	return LDB_SUCCESS;
}

static int setup_password_fields(struct setup_password_fields_io *io)
{
	bool ok;
	int ret;

	/*
	 * refuse the change if someone want to change the cleartext
	 * and supply his own hashes at the same time...
	 */
	if (io->n.cleartext && (io->n.nt_hash || io->n.lm_hash)) {
		ldb_asprintf_errstring(io->ac->module->ldb,
				       "setup_password_fields: "
				       "it's only allowed to set the cleartext password or the password hashes");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	if (io->n.cleartext && !io->n.nt_hash) {
		struct samr_Password *hash;

		hash = talloc(io->ac, struct samr_Password);
		if (!hash) {
			ldb_oom(io->ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* compute the new nt hash */
		ok = E_md4hash(io->n.cleartext, hash->hash);
		if (ok) {
			io->n.nt_hash = hash;
		} else {
			ldb_asprintf_errstring(io->ac->module->ldb,
					       "setup_password_fields: "
					       "failed to generate nthash from cleartext password");
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	if (io->n.cleartext && !io->n.lm_hash) {
		struct samr_Password *hash;

		hash = talloc(io->ac, struct samr_Password);
		if (!hash) {
			ldb_oom(io->ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* compute the new lm hash */
		ok = E_deshash(io->n.cleartext, hash->hash);
		if (ok) {
			io->n.lm_hash = hash;
		} else {
			talloc_free(hash->hash);
		}
	}

	ret = setup_nt_fields(io);
	if (ret != 0) {
		return ret;
	}

	ret = setup_lm_fields(io);
	if (ret != 0) {
		return ret;
	}

	ret = setup_supplemental_field(io);
	if (ret != 0) {
		return ret;
	}

	ret = setup_last_set_field(io);
	if (ret != 0) {
		return ret;
	}

	ret = setup_kvno_field(io);
	if (ret != 0) {
		return ret;
	}

	return LDB_SUCCESS;
}

static struct ldb_handle *ph_init_handle(struct ldb_request *req, struct ldb_module *module, enum ph_type type)
{
	struct ph_context *ac;
	struct ldb_handle *h;

	h = talloc_zero(req, struct ldb_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		return NULL;
	}

	h->module = module;

	ac = talloc_zero(h, struct ph_context);
	if (ac == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		talloc_free(h);
		return NULL;
	}

	h->private_data = (void *)ac;

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->type = type;
	ac->module = module;
	ac->orig_req = req;

	return h;
}

static int get_domain_data_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct ph_context *ac;

	ac = talloc_get_type(context, struct ph_context);

	/* we are interested only in the single reply (base search) we receive here */
	if (ares->type == LDB_REPLY_ENTRY) {
		if (ac->dom_res != NULL) {
			ldb_set_errstring(ldb, "Too many results");
			talloc_free(ares);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ac->dom_res = talloc_steal(ac, ares);
	} else {
		talloc_free(ares);
	}

	return LDB_SUCCESS;
}

static int build_domain_data_request(struct ph_context *ac)
{
	/* attrs[] is returned from this function in
	   ac->dom_req->op.search.attrs, so it must be static, as
	   otherwise the compiler can put it on the stack */
	static const char * const attrs[] = { "pwdProperties", "pwdHistoryLength", NULL };
	char *filter;

	ac->dom_req = talloc_zero(ac, struct ldb_request);
	if (ac->dom_req == NULL) {
		ldb_debug(ac->module->ldb, LDB_DEBUG_ERROR, "Out of Memory!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac->dom_req->operation = LDB_SEARCH;
	ac->dom_req->op.search.base = ldb_get_default_basedn(ac->module->ldb);
	ac->dom_req->op.search.scope = LDB_SCOPE_SUBTREE;

	filter = talloc_asprintf(ac->dom_req, "(&(objectSid=%s)(|(objectClass=domain)(objectClass=builtinDomain)))", 
				 ldap_encode_ndr_dom_sid(ac->dom_req, ac->domain_sid));
	if (filter == NULL) {
		ldb_debug(ac->module->ldb, LDB_DEBUG_ERROR, "Out of Memory!\n");
		talloc_free(ac->dom_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->dom_req->op.search.tree = ldb_parse_tree(ac->dom_req, filter);
	if (ac->dom_req->op.search.tree == NULL) {
		ldb_set_errstring(ac->module->ldb, "Invalid search filter");
		talloc_free(ac->dom_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac->dom_req->op.search.attrs = attrs;
	ac->dom_req->controls = NULL;
	ac->dom_req->context = ac;
	ac->dom_req->callback = get_domain_data_callback;
	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->dom_req);

	return LDB_SUCCESS;
}

static struct domain_data *get_domain_data(struct ldb_module *module, void *ctx, struct ldb_reply *res)
{
	struct domain_data *data;
	const char *tmp;
	struct ph_context *ac;
	char *p;

	ac = talloc_get_type(ctx, struct ph_context);

	data = talloc_zero(ac, struct domain_data);
	if (data == NULL) {
		return NULL;
	}

	if (res == NULL) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Could not find this user's domain: %s!\n", dom_sid_string(data, ac->domain_sid));
		talloc_free(data);
		return NULL;
	}

	data->pwdProperties= samdb_result_uint(res->message, "pwdProperties", 0);
	data->store_cleartext = data->pwdProperties & DOMAIN_PASSWORD_STORE_CLEARTEXT;
	data->pwdHistoryLength = samdb_result_uint(res->message, "pwdHistoryLength", 0);

	/* For a domain DN, this puts things in dotted notation */
	/* For builtin domains, this will give details for the host,
	 * but that doesn't really matter, as it's just used for salt
	 * and kerberos principals, which don't exist here */

	tmp = ldb_dn_canonical_string(ctx, res->message->dn);
	if (!tmp) {
		return NULL;
	}
	
	/* But it puts a trailing (or just before 'builtin') / on things, so kill that */
	p = strchr(tmp, '/');
	if (p) {
		p[0] = '\0';
	}

	if (tmp != NULL) {
		data->dns_domain = strlower_talloc(data, tmp);
		if (data->dns_domain == NULL) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Out of memory!\n");
			return NULL;
		}
		data->realm = strupper_talloc(data, tmp);
		if (data->realm == NULL) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Out of memory!\n");
			return NULL;
		}
		p = strchr(tmp, '.');
		if (p) {
			p[0] = '\0';
		}
		data->netbios_domain = strupper_talloc(data, tmp);
		if (data->netbios_domain == NULL) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Out of memory!\n");
			return NULL;
		}
	}

	return data;
}

static int password_hash_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_handle *h;
	struct ph_context *ac;
	struct ldb_message_element *sambaAttr;
	struct ldb_message_element *ntAttr;
	struct ldb_message_element *lmAttr;
	int ret;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "password_hash_add\n");

	if (ldb_dn_is_special(req->op.add.message->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	/* If the caller is manipulating the local passwords directly, let them pass */
	if (ldb_dn_compare_base(ldb_dn_new(req, module->ldb, LOCAL_BASE),
				req->op.add.message->dn) == 0) {
		return ldb_next_request(module, req);
	}

	/* nobody must touch this fields */
	if (ldb_msg_find_element(req->op.add.message, "ntPwdHistory")) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	if (ldb_msg_find_element(req->op.add.message, "lmPwdHistory")) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	if (ldb_msg_find_element(req->op.add.message, "supplementalCredentials")) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* If no part of this ADD touches the sambaPassword, or the NT
	 * or LM hashes, then we don't need to make any changes.  */

	sambaAttr = ldb_msg_find_element(req->op.mod.message, "sambaPassword");
	ntAttr = ldb_msg_find_element(req->op.mod.message, "unicodePwd");
	lmAttr = ldb_msg_find_element(req->op.mod.message, "dBCSPwd");

	if ((!sambaAttr) && (!ntAttr) && (!lmAttr)) {
		return ldb_next_request(module, req);
	}

	/* if it is not an entry of type person its an error */
	/* TODO: remove this when sambaPassword will be in schema */
	if (!ldb_msg_check_string_attribute(req->op.add.message, "objectClass", "person")) {
		ldb_set_errstring(module->ldb, "Cannot set a password on entry that does not have objectClass 'person'");
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}

	/* check sambaPassword is single valued here */
	/* TODO: remove this when sambaPassword will be single valued in schema */
	if (sambaAttr && sambaAttr->num_values > 1) {
		ldb_set_errstring(module->ldb, "mupltiple values for sambaPassword not allowed!\n");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	if (ntAttr && (ntAttr->num_values > 1)) {
		ldb_set_errstring(module->ldb, "mupltiple values for unicodePwd not allowed!\n");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}
	if (lmAttr && (lmAttr->num_values > 1)) {
		ldb_set_errstring(module->ldb, "mupltiple values for dBCSPwd not allowed!\n");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	if (sambaAttr && sambaAttr->num_values == 0) {
		ldb_set_errstring(module->ldb, "sambaPassword must have a value!\n");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	if (ntAttr && (ntAttr->num_values == 0)) {
		ldb_set_errstring(module->ldb, "unicodePwd must have a value!\n");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}
	if (lmAttr && (lmAttr->num_values == 0)) {
		ldb_set_errstring(module->ldb, "dBCSPwd must have a value!\n");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	h = ph_init_handle(req, module, PH_ADD);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac = talloc_get_type(h->private_data, struct ph_context);

	/* get user domain data */
	ac->domain_sid = samdb_result_sid_prefix(ac, req->op.add.message, "objectSid");
	if (ac->domain_sid == NULL) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "can't handle entry with missing objectSid!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = build_domain_data_request(ac);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->step = PH_ADD_SEARCH_DOM;

	req->handle = h;

	return ldb_next_request(module, ac->dom_req);
}

static int password_hash_add_do_add(struct ldb_handle *h) {

	struct ph_context *ac;
	struct domain_data *domain;
	struct smb_krb5_context *smb_krb5_context;
	struct ldb_message *msg;
	struct setup_password_fields_io io;
	int ret;

	ac = talloc_get_type(h->private_data, struct ph_context);

	domain = get_domain_data(ac->module, ac, ac->dom_res);
	if (domain == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->down_req = talloc(ac, struct ldb_request);
	if (ac->down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*(ac->down_req) = *(ac->orig_req);
	ac->down_req->op.add.message = msg = ldb_msg_copy_shallow(ac->down_req, ac->orig_req->op.add.message);
	if (ac->down_req->op.add.message == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Some operations below require kerberos contexts */
	if (smb_krb5_init_context(ac->down_req, 
				  ldb_get_opaque(h->module->ldb, "EventContext"), 
				  &smb_krb5_context) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ZERO_STRUCT(io);
	io.ac				= ac;
	io.domain			= domain;
	io.smb_krb5_context		= smb_krb5_context;

	io.u.user_account_control	= samdb_result_uint(msg, "userAccountControl", 0);
	io.u.sAMAccountName		= samdb_result_string(msg, "samAccountName", NULL);
	io.u.user_principal_name	= samdb_result_string(msg, "userPrincipalName", NULL);
	io.u.is_computer		= ldb_msg_check_string_attribute(msg, "objectClass", "computer");

	io.n.cleartext			= samdb_result_string(msg, "sambaPassword", NULL);
	io.n.nt_hash			= samdb_result_hash(io.ac, msg, "unicodePwd");
	io.n.lm_hash			= samdb_result_hash(io.ac, msg, "dBCSPwd");

	/* remove attributes */
	if (io.n.cleartext) ldb_msg_remove_attr(msg, "sambaPassword");
	if (io.n.nt_hash) ldb_msg_remove_attr(msg, "unicodePwd");
	if (io.n.lm_hash) ldb_msg_remove_attr(msg, "dBCSPwd");
	ldb_msg_remove_attr(msg, "pwdLastSet");
	io.o.kvno = samdb_result_uint(msg, "msDs-KeyVersionNumber", 1) - 1;
	ldb_msg_remove_attr(msg, "msDs-KeyVersionNumber");

	ret = setup_password_fields(&io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (io.g.nt_hash) {
		ret = samdb_msg_add_hash(ac->module->ldb, ac, msg,
					 "unicodePwd", io.g.nt_hash);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (io.g.lm_hash) {
		ret = samdb_msg_add_hash(ac->module->ldb, ac, msg,
					 "dBCSPwd", io.g.lm_hash);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (io.g.nt_history_len > 0) {
		ret = samdb_msg_add_hashes(ac, msg,
					   "ntPwdHistory",
					   io.g.nt_history,
					   io.g.nt_history_len);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (io.g.lm_history_len > 0) {
		ret = samdb_msg_add_hashes(ac, msg,
					   "lmPwdHistory",
					   io.g.lm_history,
					   io.g.lm_history_len);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (io.g.supplemental.length > 0) {
		ret = ldb_msg_add_value(msg, "supplementalCredentials",
					&io.g.supplemental, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	ret = samdb_msg_add_uint64(ac->module->ldb, ac, msg,
				   "pwdLastSet",
				   io.g.last_set);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	ret = samdb_msg_add_uint(ac->module->ldb, ac, msg,
				 "msDs-KeyVersionNumber",
				 io.g.kvno);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->step = PH_ADD_DO_ADD;

	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->down_req);

	/* perform the operation */
	return ldb_next_request(ac->module, ac->down_req);
}

static int password_hash_mod_search_self(struct ldb_handle *h);

static int password_hash_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_handle *h;
	struct ph_context *ac;
	struct ldb_message_element *sambaAttr;
	struct ldb_message_element *ntAttr;
	struct ldb_message_element *lmAttr;
	struct ldb_message *msg;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "password_hash_modify\n");

	if (ldb_dn_is_special(req->op.mod.message->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}
	
	/* If the caller is manipulating the local passwords directly, let them pass */
	if (ldb_dn_compare_base(ldb_dn_new(req, module->ldb, LOCAL_BASE),
				req->op.mod.message->dn) == 0) {
		return ldb_next_request(module, req);
	}

	/* nobody must touch password Histories */
	if (ldb_msg_find_element(req->op.add.message, "ntPwdHistory")) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	if (ldb_msg_find_element(req->op.add.message, "lmPwdHistory")) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	if (ldb_msg_find_element(req->op.add.message, "supplementalCredentials")) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	sambaAttr = ldb_msg_find_element(req->op.mod.message, "sambaPassword");
	ntAttr = ldb_msg_find_element(req->op.mod.message, "unicodePwd");
	lmAttr = ldb_msg_find_element(req->op.mod.message, "dBCSPwd");

	/* If no part of this touches the sambaPassword OR unicodePwd and/or dBCSPwd, then we don't
	 * need to make any changes.  For password changes/set there should
	 * be a 'delete' or a 'modify' on this attribute. */
	if ((!sambaAttr) && (!ntAttr) && (!lmAttr)) {
		return ldb_next_request(module, req);
	}

	/* check passwords are single valued here */
	/* TODO: remove this when passwords will be single valued in schema */
	if (sambaAttr && (sambaAttr->num_values > 1)) {
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}
	if (ntAttr && (ntAttr->num_values > 1)) {
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}
	if (lmAttr && (lmAttr->num_values > 1)) {
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	h = ph_init_handle(req, module, PH_MOD);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac = talloc_get_type(h->private_data, struct ph_context);

	/* return or own handle to deal with this call */
	req->handle = h;

	/* prepare the first operation */
	ac->down_req = talloc_zero(ac, struct ldb_request);
	if (ac->down_req == NULL) {
		ldb_set_errstring(module->ldb, "Out of memory!");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*(ac->down_req) = *req; /* copy the request */

	/* use a new message structure so that we can modify it */
	ac->down_req->op.mod.message = msg = ldb_msg_copy_shallow(ac->down_req, req->op.mod.message);

	/* - remove any imodification to the password from the first commit
	 *   we will make the real modification later */
	if (sambaAttr) ldb_msg_remove_attr(msg, "sambaPassword");
	if (ntAttr) ldb_msg_remove_attr(msg, "unicodePwd");
	if (lmAttr) ldb_msg_remove_attr(msg, "dBCSPwd");

	/* if there was nothing else to be modify skip to next step */
	if (msg->num_elements == 0) {
		talloc_free(ac->down_req);
		ac->down_req = NULL;
		return password_hash_mod_search_self(h);
	}
	
	ac->down_req->context = NULL;
	ac->down_req->callback = NULL;

	ac->step = PH_MOD_DO_REQ;

	ldb_set_timeout_from_prev_req(module->ldb, req, ac->down_req);

	return ldb_next_request(module, ac->down_req);
}

static int get_self_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct ph_context *ac;

	ac = talloc_get_type(context, struct ph_context);

	/* we are interested only in the single reply (base search) we receive here */
	if (ares->type == LDB_REPLY_ENTRY) {
		if (ac->search_res != NULL) {
			ldb_set_errstring(ldb, "Too many results");
			talloc_free(ares);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* if it is not an entry of type person this is an error */
		/* TODO: remove this when sambaPassword will be in schema */
		if (!ldb_msg_check_string_attribute(ares->message, "objectClass", "person")) {
			ldb_set_errstring(ldb, "Object class violation");
			talloc_free(ares);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
		}

		ac->search_res = talloc_steal(ac, ares);
	} else {
		talloc_free(ares);
	}

	return LDB_SUCCESS;
}

static int password_hash_mod_search_self(struct ldb_handle *h) {

	struct ph_context *ac;
	static const char * const attrs[] = { "userAccountControl", "lmPwdHistory", 
					      "ntPwdHistory", 
					      "objectSid", "msDS-KeyVersionNumber", 
					      "objectClass", "userPrincipalName",
					      "sAMAccountName", 
					      "dBCSPwd", "unicodePwd",
					      "supplementalCredentials",
					      NULL };

	ac = talloc_get_type(h->private_data, struct ph_context);

	/* prepare the search operation */
	ac->search_req = talloc_zero(ac, struct ldb_request);
	if (ac->search_req == NULL) {
		ldb_debug(ac->module->ldb, LDB_DEBUG_ERROR, "Out of Memory!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->search_req->operation = LDB_SEARCH;
	ac->search_req->op.search.base = ac->orig_req->op.mod.message->dn;
	ac->search_req->op.search.scope = LDB_SCOPE_BASE;
	ac->search_req->op.search.tree = ldb_parse_tree(ac->search_req, NULL);
	if (ac->search_req->op.search.tree == NULL) {
		ldb_set_errstring(ac->module->ldb, "Invalid search filter");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac->search_req->op.search.attrs = attrs;
	ac->search_req->controls = NULL;
	ac->search_req->context = ac;
	ac->search_req->callback = get_self_callback;
	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->search_req);

	ac->step = PH_MOD_SEARCH_SELF;

	return ldb_next_request(ac->module, ac->search_req);
}

static int password_hash_mod_search_dom(struct ldb_handle *h) {

	struct ph_context *ac;
	int ret;

	ac = talloc_get_type(h->private_data, struct ph_context);

	/* get object domain sid */
	ac->domain_sid = samdb_result_sid_prefix(ac, ac->search_res->message, "objectSid");
	if (ac->domain_sid == NULL) {
		ldb_debug(ac->module->ldb, LDB_DEBUG_ERROR, "can't handle entry with missing objectSid!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* get user domain data */
	ret = build_domain_data_request(ac);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->step = PH_MOD_SEARCH_DOM;

	return ldb_next_request(ac->module, ac->dom_req);
}

static int password_hash_mod_do_mod(struct ldb_handle *h) {

	struct ph_context *ac;
	struct domain_data *domain;
	struct smb_krb5_context *smb_krb5_context;
	struct ldb_message *msg;
	struct ldb_message *orig_msg;
	struct ldb_message *searched_msg;
	struct setup_password_fields_io io;
	int ret;

	ac = talloc_get_type(h->private_data, struct ph_context);

	domain = get_domain_data(ac->module, ac, ac->dom_res);
	if (domain == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->mod_req = talloc(ac, struct ldb_request);
	if (ac->mod_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*(ac->mod_req) = *(ac->orig_req);
	
	/* use a new message structure so that we can modify it */
	ac->mod_req->op.mod.message = msg = ldb_msg_new(ac->mod_req);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* modify dn */
	msg->dn = ac->orig_req->op.mod.message->dn;

	/* Some operations below require kerberos contexts */
	if (smb_krb5_init_context(ac->mod_req, 
				  ldb_get_opaque(h->module->ldb, "EventContext"), 
				  &smb_krb5_context) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	orig_msg	= discard_const(ac->orig_req->op.mod.message);
	searched_msg	= ac->search_res->message;

	ZERO_STRUCT(io);
	io.ac				= ac;
	io.domain			= domain;
	io.smb_krb5_context		= smb_krb5_context;

	io.u.user_account_control	= samdb_result_uint(searched_msg, "userAccountControl", 0);
	io.u.sAMAccountName		= samdb_result_string(searched_msg, "samAccountName", NULL);
	io.u.user_principal_name	= samdb_result_string(searched_msg, "userPrincipalName", NULL);
	io.u.is_computer		= ldb_msg_check_string_attribute(searched_msg, "objectClass", "computer");

	io.n.cleartext			= samdb_result_string(orig_msg, "sambaPassword", NULL);
	io.n.nt_hash			= samdb_result_hash(io.ac, orig_msg, "unicodePwd");
	io.n.lm_hash			= samdb_result_hash(io.ac, orig_msg, "dBCSPwd");

	io.o.kvno			= samdb_result_uint(searched_msg, "msDs-KeyVersionNumber", 0);
	io.o.nt_history_len		= samdb_result_hashes(io.ac, searched_msg, "ntPwdHistory", &io.o.nt_history);
	io.o.lm_history_len		= samdb_result_hashes(io.ac, searched_msg, "lmPwdHistory", &io.o.lm_history);
	io.o.supplemental		= ldb_msg_find_ldb_val(searched_msg, "supplementalCredentials");

	ret = setup_password_fields(&io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* make sure we replace all the old attributes */
	ret = ldb_msg_add_empty(msg, "unicodePwd", LDB_FLAG_MOD_REPLACE, NULL);
	ret = ldb_msg_add_empty(msg, "dBCSPwd", LDB_FLAG_MOD_REPLACE, NULL);
	ret = ldb_msg_add_empty(msg, "ntPwdHistory", LDB_FLAG_MOD_REPLACE, NULL);
	ret = ldb_msg_add_empty(msg, "lmPwdHistory", LDB_FLAG_MOD_REPLACE, NULL);
	ret = ldb_msg_add_empty(msg, "supplementalCredentials", LDB_FLAG_MOD_REPLACE, NULL);
	ret = ldb_msg_add_empty(msg, "pwdLastSet", LDB_FLAG_MOD_REPLACE, NULL);
	ret = ldb_msg_add_empty(msg, "msDs-KeyVersionNumber", LDB_FLAG_MOD_REPLACE, NULL);

	if (io.g.nt_hash) {
		ret = samdb_msg_add_hash(ac->module->ldb, ac, msg,
					 "unicodePwd", io.g.nt_hash);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (io.g.lm_hash) {
		ret = samdb_msg_add_hash(ac->module->ldb, ac, msg,
					 "dBCSPwd", io.g.lm_hash);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (io.g.nt_history_len > 0) {
		ret = samdb_msg_add_hashes(ac, msg,
					   "ntPwdHistory",
					   io.g.nt_history,
					   io.g.nt_history_len);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (io.g.lm_history_len > 0) {
		ret = samdb_msg_add_hashes(ac, msg,
					   "lmPwdHistory",
					   io.g.lm_history,
					   io.g.lm_history_len);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (io.g.supplemental.length > 0) {
		ret = ldb_msg_add_value(msg, "supplementalCredentials",
					&io.g.supplemental, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	ret = samdb_msg_add_uint64(ac->module->ldb, ac, msg,
				   "pwdLastSet",
				   io.g.last_set);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	ret = samdb_msg_add_uint(ac->module->ldb, ac, msg,
				 "msDs-KeyVersionNumber",
				 io.g.kvno);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->step = PH_MOD_DO_MOD;

	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->mod_req);

	/* perform the search */
	return ldb_next_request(ac->module, ac->mod_req);
}

static int ph_wait(struct ldb_handle *handle) {
	struct ph_context *ac;
	int ret;
    
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	handle->state = LDB_ASYNC_PENDING;
	handle->status = LDB_SUCCESS;

	ac = talloc_get_type(handle->private_data, struct ph_context);

	switch (ac->step) {
	case PH_ADD_SEARCH_DOM:
		ret = ldb_wait(ac->dom_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->dom_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->dom_req->handle->status;
			goto done;
		}

		if (ac->dom_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* domain search done, go on */
		return password_hash_add_do_add(handle);

	case PH_ADD_DO_ADD:
		ret = ldb_wait(ac->down_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->down_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->down_req->handle->status;
			goto done;
		}

		if (ac->down_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		break;
		
	case PH_MOD_DO_REQ:
		ret = ldb_wait(ac->down_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->down_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->down_req->handle->status;
			goto done;
		}

		if (ac->down_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* non-password mods done, go on */
		return password_hash_mod_search_self(handle);
		
	case PH_MOD_SEARCH_SELF:
		ret = ldb_wait(ac->search_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->search_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->search_req->handle->status;
			goto done;
		}

		if (ac->search_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		if (ac->search_res == NULL) {
			return LDB_ERR_NO_SUCH_OBJECT;
		}

		/* self search done, go on */
		return password_hash_mod_search_dom(handle);
		
	case PH_MOD_SEARCH_DOM:
		ret = ldb_wait(ac->dom_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->dom_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->dom_req->handle->status;
			goto done;
		}

		if (ac->dom_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* domain search done, go on */
		return password_hash_mod_do_mod(handle);

	case PH_MOD_DO_MOD:
		ret = ldb_wait(ac->mod_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->mod_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->mod_req->handle->status;
			goto done;
		}

		if (ac->mod_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		break;
		
	default:
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	ret = LDB_SUCCESS;

done:
	handle->state = LDB_ASYNC_DONE;
	return ret;
}

static int ph_wait_all(struct ldb_handle *handle) {

	int ret;

	while (handle->state != LDB_ASYNC_DONE) {
		ret = ph_wait(handle);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return handle->status;
}

static int password_hash_wait(struct ldb_handle *handle, enum ldb_wait_type type)
{
	if (type == LDB_WAIT_ALL) {
		return ph_wait_all(handle);
	} else {
		return ph_wait(handle);
	}
}

static const struct ldb_module_ops password_hash_ops = {
	.name          = "password_hash",
	.add           = password_hash_add,
	.modify        = password_hash_modify,
	.wait          = password_hash_wait
};


int password_hash_module_init(void)
{
	return ldb_register_module(&password_hash_ops);
}
