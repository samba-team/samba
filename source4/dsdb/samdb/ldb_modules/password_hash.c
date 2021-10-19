/* 
   ldb database module

   Copyright (C) Simo Sorce  2004-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2006
   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Stefan Metzmacher 2007-2010
   Copyright (C) Matthias Dieter Wallnöfer 2009-2010

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
 *  Description: correctly handle AD password changes fields
 *
 *  Author: Andrew Bartlett
 *  Author: Stefan Metzmacher
 */

#include "includes.h"
#include "ldb_module.h"
#include "libcli/auth/libcli_auth.h"
#include "libcli/security/dom_sid.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "dsdb/samdb/ldb_modules/password_modules.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "lib/crypto/md4.h"
#include "param/param.h"
#include "lib/krb5_wrap/krb5_samba.h"
#include "auth/common_auth.h"
#include "lib/messaging/messaging.h"
#include "lib/param/loadparm.h"

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/crypto.h>

#ifdef ENABLE_GPGME
#undef class
#include <gpgme.h>

/*
 * 1.2.0 is what dpkg-shlibdeps generates, based on used symbols and
 * libgpgme11.symbols
 * https://salsa.debian.org/debian/gpgme/blob/debian/master/debian/libgpgme11.symbols
 */

#define MINIMUM_GPGME_VERSION "1.2.0"
#endif

/* If we have decided there is a reason to work on this request, then
 * setup all the password hash types correctly.
 *
 * If we haven't the hashes yet but the password given as plain-text (attributes
 * 'unicodePwd', 'userPassword' and 'clearTextPassword') we have to check for
 * the constraints. Once this is done, we calculate the password hashes.
 *
 * Notice: unlike the real AD which only supports the UTF16 special based
 * 'unicodePwd' and the UTF8 based 'userPassword' plaintext attribute we
 * understand also a UTF16 based 'clearTextPassword' one.
 * The latter is also accessible through LDAP so it can also be set by external
 * tools and scripts. But be aware that this isn't portable on non SAMBA 4 ADs!
 *
 * Also when the module receives only the password hashes (possible through
 * specifying an internal LDB control - for security reasons) some checks are
 * performed depending on the operation mode (see below) (e.g. if the password
 * has been in use before if the password memory policy was activated).
 *
 * Attention: There is a difference between "modify" and "reset" operations
 * (see MS-ADTS 3.1.1.3.1.5). If the client sends a "add" and "remove"
 * operation for a password attribute we thread this as a "modify"; if it sends
 * only a "replace" one we have an (administrative) reset.
 *
 * Finally, if the administrator has requested that a password history
 * be maintained, then this should also be written out.
 *
 */

/* TODO: [consider always MS-ADTS 3.1.1.3.1.5]
 * - Check for right connection encryption
 */

/* Notice: Definition of "dsdb_control_password_change_status" moved into
 * "samdb.h" */

struct ph_context {
	struct ldb_module *module;
	struct ldb_request *req;

	struct ldb_request *dom_req;
	struct ldb_reply *dom_res;

	struct ldb_reply *pso_res;

	struct ldb_reply *search_res;

	struct ldb_message *update_msg;

	struct dsdb_control_password_change_status *status;
	struct dsdb_control_password_change *change;

	const char **gpg_key_ids;

	bool pwd_reset;
	bool change_status;
	bool hash_values;
	bool userPassword;
	bool update_password;
	bool update_lastset;
	bool pwd_last_set_bypass;
	bool pwd_last_set_default;
	bool smartcard_reset;
	const char **userPassword_schemes;
};


struct setup_password_fields_io {
	struct ph_context *ac;

	struct smb_krb5_context *smb_krb5_context;

	/* info about the user account */
	struct {
		uint32_t userAccountControl;
		NTTIME pwdLastSet;
		const char *sAMAccountName;
		const char *user_principal_name;
		const char *displayName; /* full name */
		bool is_krbtgt;
		uint32_t restrictions;
		struct dom_sid *account_sid;
	} u;

	/* new credentials and old given credentials */
	struct setup_password_fields_given {
		const struct ldb_val *cleartext_utf8;
		const struct ldb_val *cleartext_utf16;
		struct samr_Password *nt_hash;
		struct samr_Password *lm_hash;
	} n, og;

	/* old credentials */
	struct {
		struct samr_Password *nt_hash;
		struct samr_Password *lm_hash;
		uint32_t nt_history_len;
		struct samr_Password *nt_history;
		uint32_t lm_history_len;
		struct samr_Password *lm_history;
		const struct ldb_val *supplemental;
		struct supplementalCredentialsBlob scb;
	} o;

	/* generated credentials */
	struct {
		struct samr_Password *nt_hash;
		struct samr_Password *lm_hash;
		uint32_t nt_history_len;
		struct samr_Password *nt_history;
		uint32_t lm_history_len;
		struct samr_Password *lm_history;
		const char *salt;
		DATA_BLOB aes_256;
		DATA_BLOB aes_128;
		DATA_BLOB des_md5;
		DATA_BLOB des_crc;
		struct ldb_val supplemental;
		NTTIME last_set;
	} g;
};

static int msg_find_old_and_new_pwd_val(const struct ldb_message *msg,
					const char *name,
					enum ldb_request_type operation,
					const struct ldb_val **new_val,
					const struct ldb_val **old_val);

static int password_hash_bypass(struct ldb_module *module, struct ldb_request *request)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const struct ldb_message *msg;
	struct ldb_message_element *nte;
	struct ldb_message_element *lme;
	struct ldb_message_element *nthe;
	struct ldb_message_element *lmhe;
	struct ldb_message_element *sce;

	switch (request->operation) {
	case LDB_ADD:
		msg = request->op.add.message;
		break;
	case LDB_MODIFY:
		msg = request->op.mod.message;
		break;
	default:
		return ldb_next_request(module, request);
	}

	/* nobody must touch password histories and 'supplementalCredentials' */
	nte = dsdb_get_single_valued_attr(msg, "unicodePwd",
					  request->operation);
	lme = dsdb_get_single_valued_attr(msg, "dBCSPwd",
					  request->operation);
	nthe = dsdb_get_single_valued_attr(msg, "ntPwdHistory",
					   request->operation);
	lmhe = dsdb_get_single_valued_attr(msg, "lmPwdHistory",
					   request->operation);
	sce = dsdb_get_single_valued_attr(msg, "supplementalCredentials",
					  request->operation);

#define CHECK_HASH_ELEMENT(e, min, max) do {\
	if (e && e->num_values) { \
		unsigned int _count; \
		if (e->num_values != 1) { \
			return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION, \
					 "num_values != 1"); \
		} \
		if ((e->values[0].length % 16) != 0) { \
			return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION, \
					 "length % 16 != 0"); \
		} \
		_count = e->values[0].length / 16; \
		if (_count < min) { \
			return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION, \
					 "count < min"); \
		} \
		if (_count > max) { \
			return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION, \
					 "count > max"); \
		} \
	} \
} while (0)

	CHECK_HASH_ELEMENT(nte, 1, 1);
	CHECK_HASH_ELEMENT(lme, 1, 1);
	CHECK_HASH_ELEMENT(nthe, 1, INT32_MAX);
	CHECK_HASH_ELEMENT(lmhe, 1, INT32_MAX);

	if (sce && sce->num_values) {
		enum ndr_err_code ndr_err;
		struct supplementalCredentialsBlob *scb;
		struct supplementalCredentialsPackage *scpp = NULL;
		struct supplementalCredentialsPackage *scpk = NULL;
		struct supplementalCredentialsPackage *scpkn = NULL;
		struct supplementalCredentialsPackage *scpct = NULL;
		DATA_BLOB scpbp = data_blob_null;
		DATA_BLOB scpbk = data_blob_null;
		DATA_BLOB scpbkn = data_blob_null;
		DATA_BLOB scpbct = data_blob_null;
		DATA_BLOB blob;
		uint32_t i;

		if (sce->num_values != 1) {
			return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
					 "num_values != 1");
		}

		scb = talloc_zero(request, struct supplementalCredentialsBlob);
		if (!scb) {
			return ldb_module_oom(module);
		}

		ndr_err = ndr_pull_struct_blob_all(&sce->values[0], scb, scb,
				(ndr_pull_flags_fn_t)ndr_pull_supplementalCredentialsBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
					 "ndr_pull_struct_blob_all");
		}

		if (scb->sub.num_packages < 2) {
			return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
					 "num_packages < 2");
		}

		for (i=0; i < scb->sub.num_packages; i++) {
			DATA_BLOB subblob;

			subblob = strhex_to_data_blob(scb, scb->sub.packages[i].data);
			if (subblob.data == NULL) {
				return ldb_module_oom(module);
			}

			if (strcmp(scb->sub.packages[i].name, "Packages") == 0) {
				if (scpp) {
					return ldb_error(ldb,
							 LDB_ERR_CONSTRAINT_VIOLATION,
							 "Packages twice");
				}
				scpp = &scb->sub.packages[i];
				scpbp = subblob;
				continue;
			}
			if (strcmp(scb->sub.packages[i].name, "Primary:Kerberos") == 0) {
				if (scpk) {
					return ldb_error(ldb,
							 LDB_ERR_CONSTRAINT_VIOLATION,
							 "Primary:Kerberos twice");
				}
				scpk = &scb->sub.packages[i];
				scpbk = subblob;
				continue;
			}
			if (strcmp(scb->sub.packages[i].name, "Primary:Kerberos-Newer-Keys") == 0) {
				if (scpkn) {
					return ldb_error(ldb,
							 LDB_ERR_CONSTRAINT_VIOLATION,
							 "Primary:Kerberos-Newer-Keys twice");
				}
				scpkn = &scb->sub.packages[i];
				scpbkn = subblob;
				continue;
			}
			if (strcmp(scb->sub.packages[i].name, "Primary:CLEARTEXT") == 0) {
				if (scpct) {
					return ldb_error(ldb,
							 LDB_ERR_CONSTRAINT_VIOLATION,
							 "Primary:CLEARTEXT twice");
				}
				scpct = &scb->sub.packages[i];
				scpbct = subblob;
				continue;
			}

			data_blob_free(&subblob);
		}

		if (scpp == NULL) {
			return ldb_error(ldb,
					 LDB_ERR_CONSTRAINT_VIOLATION,
					 "Primary:Packages missing");
		}

		if (scpk == NULL) {
			/*
			 * If Primary:Kerberos is missing w2k8r2 reboots
			 * when a password is changed.
			 */
			return ldb_error(ldb,
					 LDB_ERR_CONSTRAINT_VIOLATION,
					 "Primary:Kerberos missing");
		}

		if (scpp) {
			struct package_PackagesBlob *p;
			uint32_t n;

			p = talloc_zero(scb, struct package_PackagesBlob);
			if (p == NULL) {
				return ldb_module_oom(module);
			}

			ndr_err = ndr_pull_struct_blob(&scpbp, p, p,
					(ndr_pull_flags_fn_t)ndr_pull_package_PackagesBlob);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "ndr_pull_struct_blob Packages");
			}

			if (p->names == NULL) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "Packages names == NULL");
			}

			for (n = 0; p->names[n]; n++) {
				/* noop */
			}

			if (scb->sub.num_packages != (n + 1)) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "Packages num_packages != num_names + 1");
			}

			talloc_free(p);
		}

		if (scpk) {
			struct package_PrimaryKerberosBlob *k;

			k = talloc_zero(scb, struct package_PrimaryKerberosBlob);
			if (k == NULL) {
				return ldb_module_oom(module);
			}

			ndr_err = ndr_pull_struct_blob(&scpbk, k, k,
					(ndr_pull_flags_fn_t)ndr_pull_package_PrimaryKerberosBlob);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "ndr_pull_struct_blob PrimaryKerberos");
			}

			if (k->version != 3) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "PrimaryKerberos version != 3");
			}

			if (k->ctr.ctr3.salt.string == NULL) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "PrimaryKerberos salt == NULL");
			}

			if (strlen(k->ctr.ctr3.salt.string) == 0) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "PrimaryKerberos strlen(salt) == 0");
			}

			if (k->ctr.ctr3.num_keys != 2) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "PrimaryKerberos num_keys != 2");
			}

			if (k->ctr.ctr3.num_old_keys > k->ctr.ctr3.num_keys) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "PrimaryKerberos num_old_keys > num_keys");
			}

			if (k->ctr.ctr3.keys[0].keytype != ENCTYPE_DES_CBC_MD5) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "PrimaryKerberos key[0] != DES_CBC_MD5");
			}
			if (k->ctr.ctr3.keys[1].keytype != ENCTYPE_DES_CBC_CRC) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "PrimaryKerberos key[1] != DES_CBC_CRC");
			}

			if (k->ctr.ctr3.keys[0].value_len != 8) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "PrimaryKerberos key[0] value_len != 8");
			}
			if (k->ctr.ctr3.keys[1].value_len != 8) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "PrimaryKerberos key[1] value_len != 8");
			}

			for (i = 0; i < k->ctr.ctr3.num_old_keys; i++) {
				if (k->ctr.ctr3.old_keys[i].keytype ==
				    k->ctr.ctr3.keys[i].keytype &&
				    k->ctr.ctr3.old_keys[i].value_len ==
				    k->ctr.ctr3.keys[i].value_len) {
					continue;
				}

				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "PrimaryKerberos old_keys type/value_len doesn't match");
			}

			talloc_free(k);
		}

		if (scpkn) {
			struct package_PrimaryKerberosBlob *k;

			k = talloc_zero(scb, struct package_PrimaryKerberosBlob);
			if (k == NULL) {
				return ldb_module_oom(module);
			}

			ndr_err = ndr_pull_struct_blob(&scpbkn, k, k,
					(ndr_pull_flags_fn_t)ndr_pull_package_PrimaryKerberosBlob);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "ndr_pull_struct_blob PrimaryKerberosNeverKeys");
			}

			if (k->version != 4) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "KerberosNerverKeys version != 4");
			}

			if (k->ctr.ctr4.salt.string == NULL) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "KerberosNewerKeys salt == NULL");
			}

			if (strlen(k->ctr.ctr4.salt.string) == 0) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "KerberosNewerKeys strlen(salt) == 0");
			}

			if (k->ctr.ctr4.num_keys != 4) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "KerberosNewerKeys num_keys != 2");
			}

			if (k->ctr.ctr4.num_old_keys > k->ctr.ctr4.num_keys) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "KerberosNewerKeys num_old_keys > num_keys");
			}

			if (k->ctr.ctr4.num_older_keys > k->ctr.ctr4.num_old_keys) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "KerberosNewerKeys num_older_keys > num_old_keys");
			}

			if (k->ctr.ctr4.keys[0].keytype != ENCTYPE_AES256_CTS_HMAC_SHA1_96) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "KerberosNewerKeys key[0] != AES256");
			}
			if (k->ctr.ctr4.keys[1].keytype != ENCTYPE_AES128_CTS_HMAC_SHA1_96) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "KerberosNewerKeys key[1] != AES128");
			}
			if (k->ctr.ctr4.keys[2].keytype != ENCTYPE_DES_CBC_MD5) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "KerberosNewerKeys key[2] != DES_CBC_MD5");
			}
			if (k->ctr.ctr4.keys[3].keytype != ENCTYPE_DES_CBC_CRC) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "KerberosNewerKeys key[3] != DES_CBC_CRC");
			}

			if (k->ctr.ctr4.keys[0].value_len != 32) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "KerberosNewerKeys key[0] value_len != 32");
			}
			if (k->ctr.ctr4.keys[1].value_len != 16) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "KerberosNewerKeys key[1] value_len != 16");
			}
			if (k->ctr.ctr4.keys[2].value_len != 8) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "KerberosNewerKeys key[2] value_len != 8");
			}
			if (k->ctr.ctr4.keys[3].value_len != 8) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "KerberosNewerKeys key[3] value_len != 8");
			}

			/*
			 * TODO:
			 * Maybe we can check old and older keys here.
			 * But we need to do some tests, if the old keys
			 * can be taken from the PrimaryKerberos blob
			 * (with only des keys), when the domain was upgraded
			 * from w2k3 to w2k8.
			 */

			talloc_free(k);
		}

		if (scpct) {
			struct package_PrimaryCLEARTEXTBlob *ct;

			ct = talloc_zero(scb, struct package_PrimaryCLEARTEXTBlob);
			if (ct == NULL) {
				return ldb_module_oom(module);
			}

			ndr_err = ndr_pull_struct_blob(&scpbct, ct, ct,
					(ndr_pull_flags_fn_t)ndr_pull_package_PrimaryCLEARTEXTBlob);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "ndr_pull_struct_blob PrimaryCLEARTEXT");
			}

			if ((ct->cleartext.length % 2) != 0) {
				return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
						 "PrimaryCLEARTEXT length % 2 != 0");
			}

			talloc_free(ct);
		}

		ndr_err = ndr_push_struct_blob(&blob, scb, scb,
				(ndr_push_flags_fn_t)ndr_push_supplementalCredentialsBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
					 "ndr_pull_struct_blob_all");
		}

		if (sce->values[0].length != blob.length) {
			return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
					 "supplementalCredentialsBlob length differ");
		}

		if (memcmp(sce->values[0].data, blob.data, blob.length) != 0) {
			return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION,
					 "supplementalCredentialsBlob memcmp differ");
		}

		talloc_free(scb);
	}

	ldb_debug(ldb, LDB_DEBUG_TRACE, "password_hash_bypass - validated\n");
	return ldb_next_request(module, request);
}

/* Get the NT hash, and fill it in as an entry in the password history, 
   and specify it into io->g.nt_hash */

static int setup_nt_fields(struct setup_password_fields_io *io)
{
	struct ldb_context *ldb;
	uint32_t i;

	io->g.nt_hash = io->n.nt_hash;
	ldb = ldb_module_get_ctx(io->ac->module);

	if (io->ac->status->domain_data.pwdHistoryLength == 0) {
		return LDB_SUCCESS;
	}

	/* We might not have an old NT password */
	io->g.nt_history = talloc_array(io->ac,
					struct samr_Password,
					io->ac->status->domain_data.pwdHistoryLength);
	if (!io->g.nt_history) {
		return ldb_oom(ldb);
	}

	for (i = 0; i < MIN(io->ac->status->domain_data.pwdHistoryLength-1,
			    io->o.nt_history_len); i++) {
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

/* Get the LANMAN hash, and fill it in as an entry in the password history, 
   and specify it into io->g.lm_hash */

static int setup_lm_fields(struct setup_password_fields_io *io)
{
	struct ldb_context *ldb;
	uint32_t i;

	io->g.lm_hash = io->n.lm_hash;
	ldb = ldb_module_get_ctx(io->ac->module);

	if (io->ac->status->domain_data.pwdHistoryLength == 0) {
		return LDB_SUCCESS;
	}

	/* We might not have an old LM password */
	io->g.lm_history = talloc_array(io->ac,
					struct samr_Password,
					io->ac->status->domain_data.pwdHistoryLength);
	if (!io->g.lm_history) {
		return ldb_oom(ldb);
	}

	for (i = 0; i < MIN(io->ac->status->domain_data.pwdHistoryLength-1,
			    io->o.lm_history_len); i++) {
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

static int setup_kerberos_keys(struct setup_password_fields_io *io)
{
	struct ldb_context *ldb;
	krb5_error_code krb5_ret;
	krb5_principal salt_principal = NULL;
	krb5_data salt_data;
	krb5_data salt;
	krb5_keyblock key;
	krb5_data cleartext_data;
	uint32_t uac_flags = 0;

	ldb = ldb_module_get_ctx(io->ac->module);
	cleartext_data.data = (char *)io->n.cleartext_utf8->data;
	cleartext_data.length = io->n.cleartext_utf8->length;

	uac_flags = io->u.userAccountControl & UF_ACCOUNT_TYPE_MASK;
	krb5_ret = smb_krb5_salt_principal(io->smb_krb5_context->krb5_context,
					   io->ac->status->domain_data.realm,
					   io->u.sAMAccountName,
					   io->u.user_principal_name,
					   uac_flags,
					   &salt_principal);
	if (krb5_ret) {
		ldb_asprintf_errstring(ldb,
				       "setup_kerberos_keys: "
				       "generation of a salting principal failed: %s",
				       smb_get_krb5_error_message(io->smb_krb5_context->krb5_context,
								  krb5_ret, io->ac));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * create salt from salt_principal
	 */
	krb5_ret = smb_krb5_get_pw_salt(io->smb_krb5_context->krb5_context,
					salt_principal, &salt_data);

	krb5_free_principal(io->smb_krb5_context->krb5_context, salt_principal);
	if (krb5_ret) {
		ldb_asprintf_errstring(ldb,
				       "setup_kerberos_keys: "
				       "generation of krb5_salt failed: %s",
				       smb_get_krb5_error_message(io->smb_krb5_context->krb5_context,
								  krb5_ret, io->ac));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* now use the talloced copy of the salt */
	salt.data	= talloc_strndup(io->ac,
					 (char *)salt_data.data,
					 salt_data.length);
	io->g.salt      = salt.data;
	salt.length	= strlen(io->g.salt);

	smb_krb5_free_data_contents(io->smb_krb5_context->krb5_context,
				    &salt_data);

	/*
	 * create ENCTYPE_AES256_CTS_HMAC_SHA1_96 key out of
	 * the salt and the cleartext password
	 */
	krb5_ret = smb_krb5_create_key_from_string(io->smb_krb5_context->krb5_context,
						   NULL,
						   &salt,
						   &cleartext_data,
						   ENCTYPE_AES256_CTS_HMAC_SHA1_96,
						   &key);
	if (krb5_ret) {
		ldb_asprintf_errstring(ldb,
				       "setup_kerberos_keys: "
				       "generation of a aes256-cts-hmac-sha1-96 key failed: %s",
				       smb_get_krb5_error_message(io->smb_krb5_context->krb5_context,
								  krb5_ret, io->ac));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	io->g.aes_256 = data_blob_talloc(io->ac,
					 KRB5_KEY_DATA(&key),
					 KRB5_KEY_LENGTH(&key));
	krb5_free_keyblock_contents(io->smb_krb5_context->krb5_context, &key);
	if (!io->g.aes_256.data) {
		return ldb_oom(ldb);
	}

	/*
	 * create ENCTYPE_AES128_CTS_HMAC_SHA1_96 key out of
	 * the salt and the cleartext password
	 */
	krb5_ret = smb_krb5_create_key_from_string(io->smb_krb5_context->krb5_context,
						   NULL,
						   &salt,
						   &cleartext_data,
						   ENCTYPE_AES128_CTS_HMAC_SHA1_96,
						   &key);
	if (krb5_ret) {
		ldb_asprintf_errstring(ldb,
				       "setup_kerberos_keys: "
				       "generation of a aes128-cts-hmac-sha1-96 key failed: %s",
				       smb_get_krb5_error_message(io->smb_krb5_context->krb5_context,
								  krb5_ret, io->ac));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	io->g.aes_128 = data_blob_talloc(io->ac,
					 KRB5_KEY_DATA(&key),
					 KRB5_KEY_LENGTH(&key));
	krb5_free_keyblock_contents(io->smb_krb5_context->krb5_context, &key);
	if (!io->g.aes_128.data) {
		return ldb_oom(ldb);
	}

	/*
	 * As per RFC-6649 single DES encryption types are no longer considered
	 * secure to be used in Kerberos, we store random keys instead of the
	 * ENCTYPE_DES_CBC_MD5 and ENCTYPE_DES_CBC_CRC keys.
	 */
	io->g.des_md5 = data_blob_talloc(io->ac, NULL, 8);
	if (!io->g.des_md5.data) {
		return ldb_oom(ldb);
	}
	generate_secret_buffer(io->g.des_md5.data, 8);

	io->g.des_crc = data_blob_talloc(io->ac, NULL, 8);
	if (!io->g.des_crc.data) {
		return ldb_oom(ldb);
	}
	generate_secret_buffer(io->g.des_crc.data, 8);

	return LDB_SUCCESS;
}

static int setup_primary_kerberos(struct setup_password_fields_io *io,
				  const struct supplementalCredentialsBlob *old_scb,
				  struct package_PrimaryKerberosBlob *pkb)
{
	struct ldb_context *ldb;
	struct package_PrimaryKerberosCtr3 *pkb3 = &pkb->ctr.ctr3;
	struct supplementalCredentialsPackage *old_scp = NULL;
	struct package_PrimaryKerberosBlob _old_pkb;
	struct package_PrimaryKerberosCtr3 *old_pkb3 = NULL;
	uint32_t i;
	enum ndr_err_code ndr_err;

	ldb = ldb_module_get_ctx(io->ac->module);

	/*
	 * prepare generation of keys
	 *
	 * ENCTYPE_DES_CBC_MD5
	 * ENCTYPE_DES_CBC_CRC
	 */
	pkb->version		= 3;
	pkb3->salt.string	= io->g.salt;
	pkb3->num_keys		= 2;
	pkb3->keys		= talloc_array(io->ac,
					       struct package_PrimaryKerberosKey3,
					       pkb3->num_keys);
	if (!pkb3->keys) {
		return ldb_oom(ldb);
	}

	pkb3->keys[0].keytype	= ENCTYPE_DES_CBC_MD5;
	pkb3->keys[0].value	= &io->g.des_md5;
	pkb3->keys[1].keytype	= ENCTYPE_DES_CBC_CRC;
	pkb3->keys[1].value	= &io->g.des_crc;

	/* initialize the old keys to zero */
	pkb3->num_old_keys	= 0;
	pkb3->old_keys		= NULL;

	/* if there're no old keys, then we're done */
	if (!old_scb) {
		return LDB_SUCCESS;
	}

	for (i=0; i < old_scb->sub.num_packages; i++) {
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

		blob = strhex_to_data_blob(io->ac, old_scp->data);
		if (!blob.data) {
			return ldb_oom(ldb);
		}

		/* TODO: use ndr_pull_struct_blob_all(), when the ndr layer handles it correct with relative pointers */
		ndr_err = ndr_pull_struct_blob(&blob, io->ac, &_old_pkb,
					       (ndr_pull_flags_fn_t)ndr_pull_package_PrimaryKerberosBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
			ldb_asprintf_errstring(ldb,
					       "setup_primary_kerberos: "
					       "failed to pull old package_PrimaryKerberosBlob: %s",
					       nt_errstr(status));
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (_old_pkb.version != 3) {
			ldb_asprintf_errstring(ldb,
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

	return LDB_SUCCESS;
}

static int setup_primary_kerberos_newer(struct setup_password_fields_io *io,
					const struct supplementalCredentialsBlob *old_scb,
					struct package_PrimaryKerberosBlob *pkb)
{
	struct ldb_context *ldb;
	struct package_PrimaryKerberosCtr4 *pkb4 = &pkb->ctr.ctr4;
	struct supplementalCredentialsPackage *old_scp = NULL;
	struct package_PrimaryKerberosBlob _old_pkb;
	struct package_PrimaryKerberosCtr4 *old_pkb4 = NULL;
	uint32_t i;
	enum ndr_err_code ndr_err;

	ldb = ldb_module_get_ctx(io->ac->module);

	/*
	 * prepare generation of keys
	 *
	 * ENCTYPE_AES256_CTS_HMAC_SHA1_96
	 * ENCTYPE_AES128_CTS_HMAC_SHA1_96
	 * ENCTYPE_DES_CBC_MD5
	 * ENCTYPE_DES_CBC_CRC
	 */
	pkb->version			= 4;
	pkb4->salt.string		= io->g.salt;
	pkb4->default_iteration_count	= 4096;
	pkb4->num_keys			= 4;

	pkb4->keys = talloc_array(io->ac,
				  struct package_PrimaryKerberosKey4,
				  pkb4->num_keys);
	if (!pkb4->keys) {
		return ldb_oom(ldb);
	}

	pkb4->keys[0].iteration_count	= 4096;
	pkb4->keys[0].keytype		= ENCTYPE_AES256_CTS_HMAC_SHA1_96;
	pkb4->keys[0].value		= &io->g.aes_256;
	pkb4->keys[1].iteration_count	= 4096;
	pkb4->keys[1].keytype		= ENCTYPE_AES128_CTS_HMAC_SHA1_96;
	pkb4->keys[1].value		= &io->g.aes_128;
	pkb4->keys[2].iteration_count	= 4096;
	pkb4->keys[2].keytype		= ENCTYPE_DES_CBC_MD5;
	pkb4->keys[2].value		= &io->g.des_md5;
	pkb4->keys[3].iteration_count	= 4096;
	pkb4->keys[3].keytype		= ENCTYPE_DES_CBC_CRC;
	pkb4->keys[3].value		= &io->g.des_crc;

	/* initialize the old keys to zero */
	pkb4->num_old_keys	= 0;
	pkb4->old_keys		= NULL;
	pkb4->num_older_keys	= 0;
	pkb4->older_keys	= NULL;

	/* if there're no old keys, then we're done */
	if (!old_scb) {
		return LDB_SUCCESS;
	}

	for (i=0; i < old_scb->sub.num_packages; i++) {
		if (strcmp("Primary:Kerberos-Newer-Keys", old_scb->sub.packages[i].name) != 0) {
			continue;
		}

		if (!old_scb->sub.packages[i].data || !old_scb->sub.packages[i].data[0]) {
			continue;
		}

		old_scp = &old_scb->sub.packages[i];
		break;
	}
	/* Primary:Kerberos-Newer-Keys element of supplementalCredentials */
	if (old_scp) {
		DATA_BLOB blob;

		blob = strhex_to_data_blob(io->ac, old_scp->data);
		if (!blob.data) {
			return ldb_oom(ldb);
		}

		/* TODO: use ndr_pull_struct_blob_all(), when the ndr layer handles it correct with relative pointers */
		ndr_err = ndr_pull_struct_blob(&blob, io->ac,
					       &_old_pkb,
					       (ndr_pull_flags_fn_t)ndr_pull_package_PrimaryKerberosBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
			ldb_asprintf_errstring(ldb,
					       "setup_primary_kerberos_newer: "
					       "failed to pull old package_PrimaryKerberosBlob: %s",
					       nt_errstr(status));
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (_old_pkb.version != 4) {
			ldb_asprintf_errstring(ldb,
					       "setup_primary_kerberos_newer: "
					       "package_PrimaryKerberosBlob version[%u] expected[4]",
					       _old_pkb.version);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		old_pkb4 = &_old_pkb.ctr.ctr4;
	}

	/* if we didn't found the old keys we're done */
	if (!old_pkb4) {
		return LDB_SUCCESS;
	}

	/* fill in the old keys */
	pkb4->num_old_keys	= old_pkb4->num_keys;
	pkb4->old_keys		= old_pkb4->keys;
	pkb4->num_older_keys	= old_pkb4->num_old_keys;
	pkb4->older_keys	= old_pkb4->old_keys;

	return LDB_SUCCESS;
}

static int setup_primary_wdigest(struct setup_password_fields_io *io,
				 const struct supplementalCredentialsBlob *old_scb,
				 struct package_PrimaryWDigestBlob *pdb)
{
	struct ldb_context *ldb = ldb_module_get_ctx(io->ac->module);
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
	 * See 3.1.1.8.11.3.1 WDIGEST_CREDENTIALS Construction
	 *     https://msdn.microsoft.com/en-us/library/cc245680.aspx
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
	 *
	 * TODO:
	 * Windows preserves the case of the DNS domain,
	 * Samba lower cases the domain at provision time
	 * This means that for mixed case Domains, the WDigest08 hash
	 * calculated by Samba differs from that calculated by Windows.
	 * Until we get a real world use case this will remain a known
	 * bug, as changing the case could have unforeseen impacts.
	 *
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
	int rc = LDB_ERR_OTHER;

	/* prepare DATA_BLOB's used in the combinations array */
	sAMAccountName		= data_blob_string_const(io->u.sAMAccountName);
	sAMAccountName_l	= data_blob_string_const(strlower_talloc(io->ac, io->u.sAMAccountName));
	if (!sAMAccountName_l.data) {
		return ldb_oom(ldb);
	}
	sAMAccountName_u	= data_blob_string_const(strupper_talloc(io->ac, io->u.sAMAccountName));
	if (!sAMAccountName_u.data) {
		return ldb_oom(ldb);
	}

	/* if the user doesn't have a userPrincipalName, create one (with lower case realm) */
	if (!user_principal_name) {
		user_principal_name = talloc_asprintf(io->ac, "%s@%s",
						      io->u.sAMAccountName,
						      io->ac->status->domain_data.dns_domain);
		if (!user_principal_name) {
			return ldb_oom(ldb);
		}	
	}
	userPrincipalName	= data_blob_string_const(user_principal_name);
	userPrincipalName_l	= data_blob_string_const(strlower_talloc(io->ac, user_principal_name));
	if (!userPrincipalName_l.data) {
		return ldb_oom(ldb);
	}
	userPrincipalName_u	= data_blob_string_const(strupper_talloc(io->ac, user_principal_name));
	if (!userPrincipalName_u.data) {
		return ldb_oom(ldb);
	}

	netbios_domain		= data_blob_string_const(io->ac->status->domain_data.netbios_domain);
	netbios_domain_l	= data_blob_string_const(strlower_talloc(io->ac,
									 io->ac->status->domain_data.netbios_domain));
	if (!netbios_domain_l.data) {
		return ldb_oom(ldb);
	}
	netbios_domain_u	= data_blob_string_const(strupper_talloc(io->ac,
									 io->ac->status->domain_data.netbios_domain));
	if (!netbios_domain_u.data) {
		return ldb_oom(ldb);
	}

	dns_domain		= data_blob_string_const(io->ac->status->domain_data.dns_domain);
	dns_domain_l		= data_blob_string_const(io->ac->status->domain_data.dns_domain);
	dns_domain_u		= data_blob_string_const(io->ac->status->domain_data.realm);

	digest			= data_blob_string_const("Digest");

	delim			= data_blob_string_const(":");
	backslash		= data_blob_string_const("\\");

	pdb->num_hashes	= ARRAY_SIZE(wdigest);
	pdb->hashes	= talloc_array(io->ac, struct package_PrimaryWDigestHash,
				       pdb->num_hashes);
	if (!pdb->hashes) {
		return ldb_oom(ldb);
	}

	for (i=0; i < ARRAY_SIZE(wdigest); i++) {
		gnutls_hash_hd_t hash_hnd = NULL;

		rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_MD5);
		if (rc < 0) {
			rc = ldb_oom(ldb);
			goto out;
		}

		if (wdigest[i].nt4dom) {
			rc = gnutls_hash(hash_hnd,
					  wdigest[i].nt4dom->data,
					  wdigest[i].nt4dom->length);
			if (rc < 0) {
				gnutls_hash_deinit(hash_hnd, NULL);
				rc = LDB_ERR_UNWILLING_TO_PERFORM;
				goto out;
			}
			rc = gnutls_hash(hash_hnd,
					  backslash.data,
					  backslash.length);
			if (rc < 0) {
				gnutls_hash_deinit(hash_hnd, NULL);
				rc = LDB_ERR_UNWILLING_TO_PERFORM;
				goto out;
			}
		}
		rc = gnutls_hash(hash_hnd,
				 wdigest[i].user->data,
				 wdigest[i].user->length);
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			rc = LDB_ERR_UNWILLING_TO_PERFORM;
			goto out;
		}
		rc = gnutls_hash(hash_hnd, delim.data, delim.length);
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			rc = LDB_ERR_UNWILLING_TO_PERFORM;
			goto out;
		}
		if (wdigest[i].realm) {
			rc = gnutls_hash(hash_hnd,
					 wdigest[i].realm->data,
					 wdigest[i].realm->length);
			if (rc < 0) {
				gnutls_hash_deinit(hash_hnd, NULL);
				rc = LDB_ERR_UNWILLING_TO_PERFORM;
				goto out;
			}
		}
		rc = gnutls_hash(hash_hnd, delim.data, delim.length);
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			rc = LDB_ERR_UNWILLING_TO_PERFORM;
			goto out;
		}
		rc = gnutls_hash(hash_hnd,
				  io->n.cleartext_utf8->data,
				  io->n.cleartext_utf8->length);
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			rc = LDB_ERR_UNWILLING_TO_PERFORM;
			goto out;
		}

		gnutls_hash_deinit(hash_hnd, pdb->hashes[i].hash);
	}

	rc = LDB_SUCCESS;
out:
	return rc;
}

#define SHA_SALT_PERMITTED_CHARS "abcdefghijklmnopqrstuvwxyz" \
				 "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
				 "0123456789./"
#define SHA_SALT_SIZE 16
#define SHA_256_SCHEME "CryptSHA256"
#define SHA_512_SCHEME "CryptSHA512"
#define CRYPT "{CRYPT}"
#define SHA_ID_LEN 3
#define SHA_256_ALGORITHM_ID 5
#define SHA_512_ALGORITHM_ID 6
#define ROUNDS_PARAMETER "rounds="

/*
 * Extract the crypt (3) algorithm number and number of hash rounds from the
 * supplied scheme string
 */
static bool parse_scheme(const char *scheme, int *algorithm, int *rounds) {

	const char *rp = NULL; /* Pointer to the 'rounds=' option */
	char digits[21];       /* digits extracted from the rounds option */
	int i = 0;             /* loop index variable */

	if (strncasecmp(SHA_256_SCHEME, scheme, strlen(SHA_256_SCHEME)) == 0) {
		*algorithm = SHA_256_ALGORITHM_ID;
	} else if (strncasecmp(SHA_512_SCHEME, scheme, strlen(SHA_256_SCHEME))
		   == 0) {
		*algorithm = SHA_512_ALGORITHM_ID;
	} else {
		return false;
	}

	rp = strcasestr(scheme, ROUNDS_PARAMETER);
	if (rp == NULL) {
		/* No options specified, use crypt default number of rounds */
		*rounds = 0;
		return true;
	}
	rp += strlen(ROUNDS_PARAMETER);
	for (i = 0; isdigit(rp[i]) && i < (sizeof(digits) - 1); i++) {
		digits[i] = rp[i];
	}
	digits[i] = '\0';
	*rounds = atoi(digits);
	return true;
}

/*
 * Calculate the password hash specified by scheme, and return it in
 * hash_value
 */
static int setup_primary_userPassword_hash(
	TALLOC_CTX *ctx,
	struct setup_password_fields_io *io,
	const char* scheme,
	struct package_PrimaryUserPasswordValue *hash_value)
{
	struct ldb_context *ldb = ldb_module_get_ctx(io->ac->module);
	const char *salt = NULL;        /* Randomly generated salt */
	const char *cmd = NULL;         /* command passed to crypt */
	const char *hash = NULL;        /* password hash generated by crypt */
	int algorithm = 0;              /* crypt hash algorithm number */
	int rounds = 0;                 /* The number of hash rounds */
	DATA_BLOB *hash_blob = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
#if defined(HAVE_CRYPT_R) || defined(HAVE_CRYPT_RN)
	struct crypt_data crypt_data = {
		.initialized = 0        /* working storage used by crypt */
	};
#endif

	/* Genrate a random password salt */
	salt = generate_random_str_list(frame,
					SHA_SALT_SIZE,
					SHA_SALT_PERMITTED_CHARS);
	if (salt == NULL) {
		TALLOC_FREE(frame);
		return ldb_oom(ldb);
	}

	/* determine the hashing algoritm and number of rounds*/
	if (!parse_scheme(scheme, &algorithm, &rounds)) {
		ldb_asprintf_errstring(
			ldb,
		        "setup_primary_userPassword: Invalid scheme of [%s] "
			"specified for 'password hash userPassword schemes' in "
			"samba.conf",
			scheme);
		TALLOC_FREE(frame);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	hash_value->scheme = talloc_strdup(ctx, CRYPT);
	hash_value->scheme_len = strlen(CRYPT) + 1;

	/* generate the id/salt parameter used by crypt */
	if (rounds) {
		cmd = talloc_asprintf(frame,
			              "$%d$rounds=%d$%s",
				      algorithm,
				      rounds,
				      salt);
	} else {
		cmd = talloc_asprintf(frame, "$%d$%s", algorithm, salt);
	}

	/*
	 * Relies on the assertion that cleartext_utf8->data is a zero
	 * terminated UTF-8 string
	 */

	/*
	 * crypt_r() and crypt() may return a null pointer upon error
	 * depending on how libcrypt was configured, so we prefer
	 * crypt_rn() from libcrypt / libxcrypt which always returns
	 * NULL on error.
	 *
	 * POSIX specifies returning a null pointer and setting
	 * errno.
	 *
	 * RHEL 7 (which does not use libcrypt / libxcrypt) returns a
	 * non-NULL pointer from crypt_r() on success but (always?)
	 * sets errno during internal processing in the NSS crypto
	 * subsystem.
	 *
	 * By preferring crypt_rn we avoid the 'return non-NULL but
	 * set-errno' that we otherwise cannot tell apart from the
	 * RHEL 7 behaviour.
	 */
	errno = 0;
#ifdef HAVE_CRYPT_RN
	hash = crypt_rn((char *)io->n.cleartext_utf8->data,
			cmd,
			&crypt_data,
			sizeof(crypt_data));
#elif HAVE_CRYPT_R
	hash = crypt_r((char *)io->n.cleartext_utf8->data, cmd, &crypt_data);
#else
	/*
	 * No crypt_r falling back to crypt, which is NOT thread safe
	 * Thread safety MT-Unsafe race:crypt
	 */
	hash = crypt((char *)io->n.cleartext_utf8->data, cmd);
#endif
	if (hash == NULL) {
		char buf[1024];
		int err = strerror_r(errno, buf, sizeof(buf));
		if (err != 0) {
			strlcpy(buf, "Unknown error", sizeof(buf)-1);
		}
		ldb_asprintf_errstring(
			ldb,
			"setup_primary_userPassword: generation of a %s "
			"password hash failed: (%s)",
			scheme,
			buf);
		TALLOC_FREE(frame);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	hash_blob = talloc_zero(ctx, DATA_BLOB);

	if (hash_blob == NULL) {
		TALLOC_FREE(frame);
		return ldb_oom(ldb);
	}

	*hash_blob =  data_blob_talloc(hash_blob,
				       (const uint8_t *)hash,
				       strlen(hash));
	if (hash_blob->data == NULL) {
		TALLOC_FREE(frame);
		return ldb_oom(ldb);
	}
	hash_value->value = hash_blob;
	TALLOC_FREE(frame);
	return LDB_SUCCESS;
}

/*
 * Calculate the desired extra password hashes
 */
static int setup_primary_userPassword(
	struct setup_password_fields_io *io,
	const struct supplementalCredentialsBlob *old_scb,
	struct package_PrimaryUserPasswordBlob *p_userPassword_b)
{
	struct ldb_context *ldb = ldb_module_get_ctx(io->ac->module);
	TALLOC_CTX *frame = talloc_stackframe();
	int i;
	int ret;

	/*
	 * Save the current nt_hash, use this to determine if the password
	 * has been changed by windows. Which will invalidate the userPassword
	 * hash. Note once NTLM-Strong-NOWTF becomes available it should be
	 * used in preference to the NT password hash
	 */
	if (io->g.nt_hash == NULL) {
		ldb_asprintf_errstring(ldb,
			"No NT Hash, unable to calculate userPassword hashes");
			return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	p_userPassword_b->current_nt_hash = *io->g.nt_hash;

	/*
	 * Determine the number of hashes
	 * Note: that currently there is no limit on the number of hashes
	 *       no checking is done on the number of schemes specified
	 *       or for uniqueness.
	 */
	p_userPassword_b->num_hashes = 0;
	for (i = 0; io->ac->userPassword_schemes[i]; i++) {
		p_userPassword_b->num_hashes++;
	}

	p_userPassword_b->hashes
		= talloc_array(io->ac,
			       struct package_PrimaryUserPasswordValue,
			       p_userPassword_b->num_hashes);
	if (p_userPassword_b->hashes == NULL) {
		TALLOC_FREE(frame);
		return ldb_oom(ldb);
	}

	for (i = 0; io->ac->userPassword_schemes[i]; i++) {
		ret = setup_primary_userPassword_hash(
			p_userPassword_b->hashes,
			io,
			io->ac->userPassword_schemes[i],
			&p_userPassword_b->hashes[i]);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(frame);
			return ret;
		}
	}
	return LDB_SUCCESS;
}


static int setup_primary_samba_gpg(struct setup_password_fields_io *io,
				   struct package_PrimarySambaGPGBlob *pgb)
{
	struct ldb_context *ldb = ldb_module_get_ctx(io->ac->module);
#ifdef ENABLE_GPGME
	gpgme_error_t gret;
	gpgme_ctx_t ctx = NULL;
	size_t num_keys = str_list_length(io->ac->gpg_key_ids);
	gpgme_key_t keys[num_keys+1];
	size_t ki = 0;
	size_t kr = 0;
	gpgme_data_t plain_data = NULL;
	gpgme_data_t crypt_data = NULL;
	size_t crypt_length = 0;
	char *crypt_mem = NULL;

	gret = gpgme_new(&ctx);
	if (gret != GPG_ERR_NO_ERROR) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "%s:%s: gret[%u] %s\n",
			  __location__, __func__,
			  gret, gpgme_strerror(gret));
		return ldb_module_operr(io->ac->module);
	}

	gpgme_set_armor(ctx, 1);

	gret = gpgme_data_new_from_mem(&plain_data,
				       (const char *)io->n.cleartext_utf16->data,
				       io->n.cleartext_utf16->length,
				       0 /* no copy */);
	if (gret != GPG_ERR_NO_ERROR) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "%s:%s: gret[%u] %s\n",
			  __location__, __func__,
			  gret, gpgme_strerror(gret));
		gpgme_release(ctx);
		return ldb_module_operr(io->ac->module);
	}
	gret = gpgme_data_new(&crypt_data);
	if (gret != GPG_ERR_NO_ERROR) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "%s:%s: gret[%u] %s\n",
			  __location__, __func__,
			  gret, gpgme_strerror(gret));
		gpgme_data_release(plain_data);
		gpgme_release(ctx);
		return ldb_module_operr(io->ac->module);
	}

	for (ki = 0; ki < num_keys; ki++) {
		const char *key_id = io->ac->gpg_key_ids[ki];
		size_t len = strlen(key_id);

		keys[ki] = NULL;

		if (len < 16) {
			ldb_debug(ldb, LDB_DEBUG_FATAL,
				  "%s:%s: ki[%zu] key_id[%s] strlen < 16, "
				  "please specify at least the 64bit key id\n",
				  __location__, __func__,
				  ki, key_id);
			for (kr = 0; keys[kr] != NULL; kr++) {
				gpgme_key_release(keys[kr]);
			}
			gpgme_data_release(crypt_data);
			gpgme_data_release(plain_data);
			gpgme_release(ctx);
			return ldb_module_operr(io->ac->module);
		}

		gret = gpgme_get_key(ctx, key_id, &keys[ki], 0 /* public key */);
		if (gret != GPG_ERR_NO_ERROR) {
			keys[ki] = NULL;
			if (gpg_err_source(gret) == GPG_ERR_SOURCE_GPGME
			    && gpg_err_code(gret) == GPG_ERR_EOF) {
				ldb_debug(ldb, LDB_DEBUG_ERROR,
					  "Invalid "
					  "'password hash gpg key ids': "
					  "Public Key ID [%s] "
					  "not found in keyring\n",
					  key_id);

			} else {
				ldb_debug(ldb, LDB_DEBUG_ERROR,
					  "%s:%s: ki[%zu] key_id[%s] "
					  "gret[%u] %s\n",
					  __location__, __func__,
					  ki, key_id,
					  gret, gpgme_strerror(gret));
			}
			for (kr = 0; keys[kr] != NULL; kr++) {
				gpgme_key_release(keys[kr]);
			}
			gpgme_data_release(crypt_data);
			gpgme_data_release(plain_data);
			gpgme_release(ctx);
			return ldb_module_operr(io->ac->module);
		}
	}
	keys[ki] = NULL;

	gret = gpgme_op_encrypt(ctx, keys,
				GPGME_ENCRYPT_ALWAYS_TRUST,
				plain_data, crypt_data);
	gpgme_data_release(plain_data);
	plain_data = NULL;
	for (kr = 0; keys[kr] != NULL; kr++) {
		gpgme_key_release(keys[kr]);
		keys[kr] = NULL;
	}
	gpgme_release(ctx);
	ctx = NULL;
	if (gret != GPG_ERR_NO_ERROR) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "%s:%s: gret[%u] %s\n",
			  __location__, __func__,
			  gret, gpgme_strerror(gret));
		gpgme_data_release(crypt_data);
		return ldb_module_operr(io->ac->module);
	}

	crypt_mem = gpgme_data_release_and_get_mem(crypt_data, &crypt_length);
	crypt_data = NULL;
	if (crypt_mem == NULL) {
		return ldb_module_oom(io->ac->module);
	}

	pgb->gpg_blob = data_blob_talloc(io->ac,
					 (const uint8_t *)crypt_mem,
					 crypt_length);
	gpgme_free(crypt_mem);
	crypt_mem = NULL;
	crypt_length = 0;
	if (pgb->gpg_blob.data == NULL) {
		return ldb_module_oom(io->ac->module);
	}

	return LDB_SUCCESS;
#else /* ENABLE_GPGME */
	ldb_debug_set(ldb, LDB_DEBUG_FATAL,
		      "You configured 'password hash gpg key ids', "
		      "but GPGME support is missing. (%s:%d)",
		      __FILE__, __LINE__);
	return LDB_ERR_UNWILLING_TO_PERFORM;
#endif /* else ENABLE_GPGME */
}

#define NUM_PACKAGES 6
static int setup_supplemental_field(struct setup_password_fields_io *io)
{
	struct ldb_context *ldb;
	struct supplementalCredentialsBlob scb;
	struct supplementalCredentialsBlob *old_scb = NULL;
	/*
	 * Packages +
	 * ( Kerberos-Newer-Keys, Kerberos,
	 *   WDigest, CLEARTEXT, userPassword, SambaGPG)
	 */
	uint32_t num_names = 0;
	const char *names[1+NUM_PACKAGES];
	uint32_t num_packages = 0;
	struct supplementalCredentialsPackage packages[1+NUM_PACKAGES];
	struct supplementalCredentialsPackage *pp = packages;
	int ret;
	enum ndr_err_code ndr_err;
	bool do_newer_keys = false;
	bool do_cleartext = false;
	bool do_samba_gpg = false;
	struct loadparm_context *lp_ctx = NULL;

	ZERO_STRUCT(names);
	ZERO_STRUCT(packages);

	ldb = ldb_module_get_ctx(io->ac->module);
	lp_ctx = talloc_get_type(ldb_get_opaque(ldb, "loadparm"),
				 struct loadparm_context);

	if (!io->n.cleartext_utf8) {
		/*
		 * when we don't have a cleartext password
		 * we can't setup a supplementalCredential value
		 */
		return LDB_SUCCESS;
	}

	/* if there's an old supplementaCredentials blob then use it */
	if (io->o.supplemental) {
		if (io->o.scb.sub.signature == SUPPLEMENTAL_CREDENTIALS_SIGNATURE) {
			old_scb = &io->o.scb;
		} else {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "setup_supplemental_field: "
				  "supplementalCredentialsBlob "
				  "signature[0x%04X] expected[0x%04X]",
				  io->o.scb.sub.signature,
				  SUPPLEMENTAL_CREDENTIALS_SIGNATURE);
		}
	}
	/* Per MS-SAMR 3.1.1.8.11.6 we create AES keys if our domain functionality level is 2008 or higher */



	/*
	 * The ordering is this
	 *
	 * Primary:Kerberos-Newer-Keys (optional)
	 * Primary:Kerberos
	 * Primary:WDigest
	 * Primary:CLEARTEXT (optional)
	 * Primary:userPassword
	 * Primary:SambaGPG (optional)
	 *
	 * And the 'Packages' package is insert before the last
	 * other package.
	 *
	 * Note: it's important that Primary:SambaGPG is added as
	 * the last element. This is the indication that it matches
	 * the current password. When a password change happens on
	 * a Windows DC, it will keep the old Primary:SambaGPG value,
	 * but as the first element.
	 */
	do_newer_keys = (dsdb_functional_level(ldb) >= DS_DOMAIN_FUNCTION_2008);
	if (do_newer_keys) {
		struct package_PrimaryKerberosBlob pknb;
		DATA_BLOB pknb_blob;
		char *pknb_hexstr;
		/*
		 * setup 'Primary:Kerberos-Newer-Keys' element
		 */
		names[num_names++] = "Kerberos-Newer-Keys";

		ret = setup_primary_kerberos_newer(io, old_scb, &pknb);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		ndr_err = ndr_push_struct_blob(
			&pknb_blob, io->ac,
			&pknb,
			(ndr_push_flags_fn_t)ndr_push_package_PrimaryKerberosBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
			ldb_asprintf_errstring(
				ldb,
				"setup_supplemental_field: "
				"failed to push "
				"package_PrimaryKerberosNeverBlob: %s",
				nt_errstr(status));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		pknb_hexstr = data_blob_hex_string_upper(io->ac, &pknb_blob);
		if (!pknb_hexstr) {
			return ldb_oom(ldb);
		}
		pp->name	= "Primary:Kerberos-Newer-Keys";
		pp->reserved	= 1;
		pp->data	= pknb_hexstr;
		pp++;
		num_packages++;
	}

	{
		/*
		 * setup 'Primary:Kerberos' element
		 */
		/* Primary:Kerberos */
		struct package_PrimaryKerberosBlob pkb;
		DATA_BLOB pkb_blob;
		char *pkb_hexstr;

		names[num_names++] = "Kerberos";

		ret = setup_primary_kerberos(io, old_scb, &pkb);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		ndr_err = ndr_push_struct_blob(
			&pkb_blob, io->ac,
			&pkb,
			(ndr_push_flags_fn_t)ndr_push_package_PrimaryKerberosBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
			ldb_asprintf_errstring(
				ldb,
				"setup_supplemental_field: "
				"failed to push package_PrimaryKerberosBlob: %s",
				nt_errstr(status));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		pkb_hexstr = data_blob_hex_string_upper(io->ac, &pkb_blob);
		if (!pkb_hexstr) {
			return ldb_oom(ldb);
		}
		pp->name	= "Primary:Kerberos";
		pp->reserved	= 1;
		pp->data	= pkb_hexstr;
		pp++;
		num_packages++;
	}

	if (lpcfg_weak_crypto(lp_ctx) == SAMBA_WEAK_CRYPTO_ALLOWED) {
		/*
		 * setup 'Primary:WDigest' element
		 */
		struct package_PrimaryWDigestBlob pdb;
		DATA_BLOB pdb_blob;
		char *pdb_hexstr;

		names[num_names++] = "WDigest";

		ret = setup_primary_wdigest(io, old_scb, &pdb);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		ndr_err = ndr_push_struct_blob(
			&pdb_blob, io->ac,
			&pdb,
			(ndr_push_flags_fn_t)ndr_push_package_PrimaryWDigestBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
			ldb_asprintf_errstring(
				ldb,
				"setup_supplemental_field: "
				"failed to push package_PrimaryWDigestBlob: %s",
				nt_errstr(status));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		pdb_hexstr = data_blob_hex_string_upper(io->ac, &pdb_blob);
		if (!pdb_hexstr) {
			return ldb_oom(ldb);
		}
		pp->name	= "Primary:WDigest";
		pp->reserved	= 1;
		pp->data	= pdb_hexstr;
		pp++;
		num_packages++;
	}

	/*
	 * setup 'Primary:CLEARTEXT' element
	 */
	if (io->ac->status->domain_data.store_cleartext &&
	    (io->u.userAccountControl & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED)) {
		do_cleartext = true;
	}
	if (do_cleartext) {
		struct package_PrimaryCLEARTEXTBlob pcb;
		DATA_BLOB pcb_blob;
		char *pcb_hexstr;

		names[num_names++] = "CLEARTEXT";

		pcb.cleartext	= *io->n.cleartext_utf16;

		ndr_err = ndr_push_struct_blob(
			&pcb_blob, io->ac,
			&pcb,
			(ndr_push_flags_fn_t)ndr_push_package_PrimaryCLEARTEXTBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
			ldb_asprintf_errstring(
				ldb,
				"setup_supplemental_field: "
				"failed to push package_PrimaryCLEARTEXTBlob: %s",
				nt_errstr(status));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		pcb_hexstr = data_blob_hex_string_upper(io->ac, &pcb_blob);
		if (!pcb_hexstr) {
			return ldb_oom(ldb);
		}
		pp->name	= "Primary:CLEARTEXT";
		pp->reserved	= 1;
		pp->data	= pcb_hexstr;
		pp++;
		num_packages++;
	}

	if (io->ac->userPassword_schemes) {
		/*
		 * setup 'Primary:userPassword' element
		 */
		struct package_PrimaryUserPasswordBlob
			p_userPassword_b;
		DATA_BLOB p_userPassword_b_blob;
		char *p_userPassword_b_hexstr;

		names[num_names++] = "userPassword";

		ret = setup_primary_userPassword(io,
						 old_scb,
						 &p_userPassword_b);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		ndr_err = ndr_push_struct_blob(
			&p_userPassword_b_blob,
			io->ac,
			&p_userPassword_b,
			(ndr_push_flags_fn_t)
			ndr_push_package_PrimaryUserPasswordBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
			ldb_asprintf_errstring(
				ldb,
				"setup_supplemental_field: failed to push "
				"package_PrimaryUserPasswordBlob: %s",
				nt_errstr(status));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		p_userPassword_b_hexstr
			= data_blob_hex_string_upper(
				io->ac,
				&p_userPassword_b_blob);
		if (!p_userPassword_b_hexstr) {
			return ldb_oom(ldb);
		}
		pp->name     = "Primary:userPassword";
		pp->reserved = 1;
		pp->data     = p_userPassword_b_hexstr;
		pp++;
		num_packages++;
	}

	/*
	 * setup 'Primary:SambaGPG' element
	 */
	if (io->ac->gpg_key_ids != NULL) {
		do_samba_gpg = true;
	}
	if (do_samba_gpg) {
		struct package_PrimarySambaGPGBlob pgb;
		DATA_BLOB pgb_blob;
		char *pgb_hexstr;

		names[num_names++] = "SambaGPG";

		ret = setup_primary_samba_gpg(io, &pgb);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		ndr_err = ndr_push_struct_blob(&pgb_blob, io->ac, &pgb,
			(ndr_push_flags_fn_t)ndr_push_package_PrimarySambaGPGBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
			ldb_asprintf_errstring(ldb,
					"setup_supplemental_field: failed to "
					"push package_PrimarySambaGPGBlob: %s",
					nt_errstr(status));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		pgb_hexstr = data_blob_hex_string_upper(io->ac, &pgb_blob);
		if (!pgb_hexstr) {
			return ldb_oom(ldb);
		}
		pp->name	= "Primary:SambaGPG";
		pp->reserved	= 1;
		pp->data	= pgb_hexstr;
		pp++;
		num_packages++;
	}

	/*
	 * setup 'Packages' element
	 */
	{
		struct package_PackagesBlob pb;
		DATA_BLOB pb_blob;
		char *pb_hexstr;

		pb.names = names;
		ndr_err = ndr_push_struct_blob(
			&pb_blob, io->ac,
			&pb,
			(ndr_push_flags_fn_t)ndr_push_package_PackagesBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
			ldb_asprintf_errstring(
				ldb,
				"setup_supplemental_field: "
				"failed to push package_PackagesBlob: %s",
				nt_errstr(status));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		pb_hexstr = data_blob_hex_string_upper(io->ac, &pb_blob);
		if (!pb_hexstr) {
			return ldb_oom(ldb);
		}
		pp->name	= "Packages";
		pp->reserved	= 2;
		pp->data	= pb_hexstr;
		num_packages++;
		/*
		 * We don't increment pp so it's pointing to the last package
		 */
	}

	/*
	 * setup 'supplementalCredentials' value
	 */
	{
		/*
		 * The 'Packages' element needs to be the second last element
		 * in supplementalCredentials
		 */
		struct supplementalCredentialsPackage temp;
		struct supplementalCredentialsPackage *prev;

		prev = pp-1;
		temp = *prev;
		*prev = *pp;
		*pp = temp;

		ZERO_STRUCT(scb);
		scb.sub.signature	= SUPPLEMENTAL_CREDENTIALS_SIGNATURE;
		scb.sub.num_packages	= num_packages;
		scb.sub.packages	= packages;

		ndr_err = ndr_push_struct_blob(
			&io->g.supplemental, io->ac,
			&scb,
			(ndr_push_flags_fn_t)ndr_push_supplementalCredentialsBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
			ldb_asprintf_errstring(
				ldb,
				"setup_supplemental_field: "
				"failed to push supplementalCredentialsBlob: %s",
				nt_errstr(status));
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	return LDB_SUCCESS;
}

static int setup_last_set_field(struct setup_password_fields_io *io)
{
	struct ldb_context *ldb = ldb_module_get_ctx(io->ac->module);
	const struct ldb_message *msg = NULL;
	struct timeval tv = { .tv_sec = 0 };
	const struct ldb_val *old_val = NULL;
	const struct ldb_val *new_val = NULL;
	int ret;

	switch (io->ac->req->operation) {
	case LDB_ADD:
		msg = io->ac->req->op.add.message;
		break;
	case LDB_MODIFY:
		msg = io->ac->req->op.mod.message;
		break;
	default:
		return LDB_ERR_OPERATIONS_ERROR;
		break;
	}

	if (io->ac->pwd_last_set_bypass) {
		struct ldb_message_element *el1 = NULL;
		struct ldb_message_element *el2 = NULL;

		if (msg == NULL) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		el1 = dsdb_get_single_valued_attr(msg, "pwdLastSet",
						  io->ac->req->operation);
		if (el1 == NULL) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		el2 = ldb_msg_find_element(msg, "pwdLastSet");
		if (el2 == NULL) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if (el1 != el2) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		io->g.last_set = samdb_result_nttime(msg, "pwdLastSet", 0);
		return LDB_SUCCESS;
	}

	ret = msg_find_old_and_new_pwd_val(msg, "pwdLastSet",
					   io->ac->req->operation,
					   &new_val, &old_val);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (old_val != NULL && new_val == NULL) {
		ldb_set_errstring(ldb,
				  "'pwdLastSet' deletion is not allowed!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	io->g.last_set = UINT64_MAX;
	if (new_val != NULL) {
		struct ldb_message *tmp_msg = NULL;

		tmp_msg = ldb_msg_new(io->ac);
		if (tmp_msg == NULL) {
			return ldb_module_oom(io->ac->module);
		}

		if (old_val != NULL) {
			NTTIME old_last_set = 0;

			ret = ldb_msg_add_value(tmp_msg, "oldval",
						old_val, NULL);
			if (ret != LDB_SUCCESS) {
				return ret;
			}

			old_last_set = samdb_result_nttime(tmp_msg,
							   "oldval",
							   1);
			if (io->u.pwdLastSet != old_last_set) {
				return dsdb_module_werror(io->ac->module,
					LDB_ERR_NO_SUCH_ATTRIBUTE,
					WERR_DS_CANT_REM_MISSING_ATT_VAL,
					"setup_last_set_field: old pwdLastSet "
					"value not found!");
			}
		}

		ret = ldb_msg_add_value(tmp_msg, "newval",
					new_val, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		io->g.last_set = samdb_result_nttime(tmp_msg,
						     "newval",
						     1);
	} else if (ldb_msg_find_element(msg, "pwdLastSet")) {
		ldb_set_errstring(ldb,
				  "'pwdLastSet' deletion is not allowed!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	} else if (io->ac->smartcard_reset) {
		/*
		 * adding UF_SMARTCARD_REQUIRED doesn't update
		 * pwdLastSet implicitly.
		 */
		io->ac->update_lastset = false;
	}

	/* only 0 or -1 (0xFFFFFFFFFFFFFFFF) are allowed */
	switch (io->g.last_set) {
	case 0:
		if (!io->ac->pwd_last_set_default) {
			break;
		}
		if (!io->ac->update_password) {
			break;
		}
		FALL_THROUGH;
	case UINT64_MAX:
		if (!io->ac->update_password &&
		    io->u.pwdLastSet != 0 &&
		    io->u.pwdLastSet != UINT64_MAX)
		{
			/*
			 * Just setting pwdLastSet to -1, while not changing
			 * any password field has no effect if pwdLastSet
			 * is already non-zero.
			 */
			io->ac->update_lastset = false;
			break;
		}
		/* -1 means set it as now */
		GetTimeOfDay(&tv);
		io->g.last_set = timeval_to_nttime(&tv);
		break;
	default:
		return dsdb_module_werror(io->ac->module,
					  LDB_ERR_OTHER,
					  WERR_INVALID_PARAMETER,
					  "setup_last_set_field: "
					  "pwdLastSet must be 0 or -1 only!");
	}

	if (io->ac->req->operation == LDB_ADD) {
		/*
		 * We always need to store the value on add
		 * operations.
		 */
		return LDB_SUCCESS;
	}

	if (io->g.last_set == io->u.pwdLastSet) {
		/*
		 * Just setting pwdLastSet to 0, is no-op if it's already 0.
		 */
		io->ac->update_lastset = false;
	}

	return LDB_SUCCESS;
}

static int setup_given_passwords(struct setup_password_fields_io *io,
				 struct setup_password_fields_given *g)
{
	struct ldb_context *ldb;
	bool ok;

	ldb = ldb_module_get_ctx(io->ac->module);

	if (g->cleartext_utf8) {
		struct ldb_val *cleartext_utf16_blob;

		cleartext_utf16_blob = talloc(io->ac, struct ldb_val);
		if (!cleartext_utf16_blob) {
			return ldb_oom(ldb);
		}
		if (!convert_string_talloc(io->ac,
					   CH_UTF8, CH_UTF16,
					   g->cleartext_utf8->data,
					   g->cleartext_utf8->length,
					   (void *)&cleartext_utf16_blob->data,
					   &cleartext_utf16_blob->length)) {
			if (g->cleartext_utf8->length != 0) {
				talloc_free(cleartext_utf16_blob);
				ldb_asprintf_errstring(ldb,
						       "setup_password_fields: "
						       "failed to generate UTF16 password from cleartext UTF8 one for user '%s'!",
						       io->u.sAMAccountName);
				return LDB_ERR_CONSTRAINT_VIOLATION;
			} else {
				/* passwords with length "0" are valid! */
				cleartext_utf16_blob->data = NULL;
				cleartext_utf16_blob->length = 0;
			}
		}
		g->cleartext_utf16 = cleartext_utf16_blob;
	} else if (g->cleartext_utf16) {
		struct ldb_val *cleartext_utf8_blob;

		cleartext_utf8_blob = talloc(io->ac, struct ldb_val);
		if (!cleartext_utf8_blob) {
			return ldb_oom(ldb);
		}
		if (!convert_string_talloc(io->ac,
					   CH_UTF16MUNGED, CH_UTF8,
					   g->cleartext_utf16->data,
					   g->cleartext_utf16->length,
					   (void *)&cleartext_utf8_blob->data,
					   &cleartext_utf8_blob->length)) {
			if (g->cleartext_utf16->length != 0) {
				/* We must bail out here, the input wasn't even
				 * a multiple of 2 bytes */
				talloc_free(cleartext_utf8_blob);
				ldb_asprintf_errstring(ldb,
						       "setup_password_fields: "
						       "failed to generate UTF8 password from cleartext UTF 16 one for user '%s' - the latter had odd length (length must be a multiple of 2)!",
						       io->u.sAMAccountName);
				return LDB_ERR_CONSTRAINT_VIOLATION;
			} else {
				/* passwords with length "0" are valid! */
				cleartext_utf8_blob->data = NULL;
				cleartext_utf8_blob->length = 0;
			}
		}
		g->cleartext_utf8 = cleartext_utf8_blob;
	}

	if (g->cleartext_utf16) {
		struct samr_Password *nt_hash;

		nt_hash = talloc(io->ac, struct samr_Password);
		if (!nt_hash) {
			return ldb_oom(ldb);
		}
		g->nt_hash = nt_hash;

		/* compute the new nt hash */
		mdfour(nt_hash->hash,
		       g->cleartext_utf16->data,
		       g->cleartext_utf16->length);
	}

	if (g->cleartext_utf8) {
		struct samr_Password *lm_hash;

		lm_hash = talloc(io->ac, struct samr_Password);
		if (!lm_hash) {
			return ldb_oom(ldb);
		}

		/* compute the new lm hash */
		ok = E_deshash((char *)g->cleartext_utf8->data, lm_hash->hash);
		if (ok) {
			g->lm_hash = lm_hash;
		} else {
			talloc_free(lm_hash);
		}
	}

	return LDB_SUCCESS;
}

static int setup_password_fields(struct setup_password_fields_io *io)
{
	struct ldb_context *ldb = ldb_module_get_ctx(io->ac->module);
	struct loadparm_context *lp_ctx =
		talloc_get_type(ldb_get_opaque(ldb, "loadparm"),
				struct loadparm_context);
	int ret;

	ret = setup_last_set_field(io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (!io->ac->update_password) {
		return LDB_SUCCESS;
	}

	/* transform the old password (for password changes) */
	ret = setup_given_passwords(io, &io->og);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* transform the new password */
	ret = setup_given_passwords(io, &io->n);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (io->n.cleartext_utf8) {
		ret = setup_kerberos_keys(io);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	ret = setup_nt_fields(io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (lpcfg_lanman_auth(lp_ctx)) {
		ret = setup_lm_fields(io);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	} else {
		io->g.lm_hash = NULL;
		io->g.lm_history_len = 0;
	}

	ret = setup_supplemental_field(io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

static int setup_smartcard_reset(struct setup_password_fields_io *io)
{
	struct ldb_context *ldb = ldb_module_get_ctx(io->ac->module);
	struct loadparm_context *lp_ctx = talloc_get_type(
		ldb_get_opaque(ldb, "loadparm"), struct loadparm_context);
	struct supplementalCredentialsBlob scb = { .__ndr_size = 0 };
	enum ndr_err_code ndr_err;

	if (!io->ac->smartcard_reset) {
		return LDB_SUCCESS;
	}

	io->g.nt_hash = talloc(io->ac, struct samr_Password);
	if (io->g.nt_hash == NULL) {
		return ldb_module_oom(io->ac->module);
	}
	generate_secret_buffer(io->g.nt_hash->hash,
			       sizeof(io->g.nt_hash->hash));
	io->g.nt_history_len = 0;

	if (lpcfg_lanman_auth(lp_ctx)) {
		io->g.lm_hash = talloc(io->ac, struct samr_Password);
		if (io->g.lm_hash == NULL) {
			return ldb_module_oom(io->ac->module);
		}
		generate_secret_buffer(io->g.lm_hash->hash,
				       sizeof(io->g.lm_hash->hash));
	} else {
		io->g.lm_hash = NULL;
	}
	io->g.lm_history_len = 0;

	/*
	 * We take the "old" value and store it
	 * with num_packages = 0.
	 *
	 * On "add" we have scb.sub.signature == 0, which
	 * results in:
	 *
	 * [0000] 00 00 00 00 00 00 00 00   00 00 00 00 00
	 *
	 * On modify it's likely to be scb.sub.signature ==
	 * SUPPLEMENTAL_CREDENTIALS_SIGNATURE (0x0050), which results in
	 * something like:
	 *
	 * [0000] 00 00 00 00 62 00 00 00   00 00 00 00 20 00 20 00
	 * [0010] 20 00 20 00 20 00 20 00   20 00 20 00 20 00 20 00
	 * [0020] 20 00 20 00 20 00 20 00   20 00 20 00 20 00 20 00
	 * [0030] 20 00 20 00 20 00 20 00   20 00 20 00 20 00 20 00
	 * [0040] 20 00 20 00 20 00 20 00   20 00 20 00 20 00 20 00
	 * [0050] 20 00 20 00 20 00 20 00   20 00 20 00 20 00 20 00
	 * [0060] 20 00 20 00 20 00 20 00   20 00 20 00 50 00 00
	 *
	 * See https://bugzilla.samba.org/show_bug.cgi?id=11441
	 * and ndr_{push,pull}_supplementalCredentialsSubBlob().
	 */
	scb = io->o.scb;
	scb.sub.num_packages = 0;

	/*
	 * setup 'supplementalCredentials' value without packages
	 */
	ndr_err = ndr_push_struct_blob(&io->g.supplemental, io->ac,
				       &scb,
				       (ndr_push_flags_fn_t)ndr_push_supplementalCredentialsBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
		ldb_asprintf_errstring(ldb,
				       "setup_smartcard_reset: "
				       "failed to push supplementalCredentialsBlob: %s",
				       nt_errstr(status));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	io->ac->update_password = true;
	return LDB_SUCCESS;
}

static int make_error_and_update_badPwdCount(struct setup_password_fields_io *io, WERROR *werror)
{
	struct ldb_context *ldb = ldb_module_get_ctx(io->ac->module);
	struct ldb_message *mod_msg = NULL;
	struct ldb_message *pso_msg = NULL;
	NTSTATUS status;
	int ret;

	/* PSO search result is optional (NULL if no PSO applies) */
	if (io->ac->pso_res != NULL) {
		pso_msg = io->ac->pso_res->message;
	}

	status = dsdb_update_bad_pwd_count(io->ac, ldb,
					   io->ac->search_res->message,
					   io->ac->dom_res->message,
					   pso_msg,
					   &mod_msg);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (mod_msg == NULL) {
		goto done;
	}

	/*
	 * OK, horrible semantics ahead.
	 *
	 * - We need to abort any existing transaction
	 * - create a transaction arround the badPwdCount update
	 * - re-open the transaction so the upper layer
	 *   doesn't know what happened.
	 *
	 * This is needed because returning an error to the upper
	 * layer will cancel the transaction and undo the badPwdCount
	 * update.
	 */

	/*
	 * Checking errors here is a bit pointless.
	 * What can we do if we can't end the transaction?
	 */
	ret = ldb_next_del_trans(io->ac->module);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "Failed to abort transaction prior to update of badPwdCount of %s: %s",
			  ldb_dn_get_linearized(io->ac->search_res->message->dn),
			  ldb_errstring(ldb));
		/*
		 * just return the original error
		 */
		goto done;
	}

	/* Likewise, what should we do if we can't open a new transaction? */
	ret = ldb_next_start_trans(io->ac->module);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Failed to open transaction to update badPwdCount of %s: %s",
			  ldb_dn_get_linearized(io->ac->search_res->message->dn),
			  ldb_errstring(ldb));
		/*
		 * just return the original error
		 */
		goto done;
	}

	ret = dsdb_module_modify(io->ac->module, mod_msg,
				 DSDB_FLAG_NEXT_MODULE,
				 io->ac->req);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Failed to update badPwdCount of %s: %s",
			  ldb_dn_get_linearized(io->ac->search_res->message->dn),
			  ldb_errstring(ldb));
		/*
		 * We can only ignore this...
		 */
	}

	ret = ldb_next_end_trans(io->ac->module);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Failed to close transaction to update badPwdCount of %s: %s",
			  ldb_dn_get_linearized(io->ac->search_res->message->dn),
			  ldb_errstring(ldb));
		/*
		 * We can only ignore this...
		 */
	}

	ret = ldb_next_start_trans(io->ac->module);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Failed to open transaction after update of badPwdCount of %s: %s",
			  ldb_dn_get_linearized(io->ac->search_res->message->dn),
			  ldb_errstring(ldb));
		/*
		 * We can only ignore this...
		 */
	}

done:
	ret = LDB_ERR_CONSTRAINT_VIOLATION;
	*werror = WERR_INVALID_PASSWORD;
	ldb_asprintf_errstring(ldb,
			       "%08X: %s - check_password_restrictions: "
			       "The old password specified doesn't match!",
			       W_ERROR_V(*werror),
			       ldb_strerror(ret));
	return ret;
}

static int check_password_restrictions(struct setup_password_fields_io *io, WERROR *werror)
{
	struct ldb_context *ldb = ldb_module_get_ctx(io->ac->module);
	int ret;
	struct loadparm_context *lp_ctx =
		talloc_get_type(ldb_get_opaque(ldb, "loadparm"),
				struct loadparm_context);

	*werror = WERR_INVALID_PARAMETER;

	if (!io->ac->update_password) {
		return LDB_SUCCESS;
	}

	/* First check the old password is correct, for password changes */
	if (!io->ac->pwd_reset) {
		bool nt_hash_checked = false;

		/* we need the old nt or lm hash given by the client */
		if (!io->og.nt_hash && !io->og.lm_hash) {
			ldb_asprintf_errstring(ldb,
				"check_password_restrictions: "
				"You need to provide the old password in order "
				"to change it!");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		/* The password modify through the NT hash is encouraged and
		   has no problems at all */
		if (io->og.nt_hash) {
			if (!io->o.nt_hash || memcmp(io->og.nt_hash->hash, io->o.nt_hash->hash, 16) != 0) {
				return make_error_and_update_badPwdCount(io, werror);
			}

			nt_hash_checked = true;
		}

		/* But it is also possible to change a password by the LM hash
		 * alone for compatibility reasons. This check is optional if
		 * the NT hash was already checked - otherwise it's mandatory.
		 * (as the SAMR operations request it). */
		if (io->og.lm_hash) {
			if ((!io->o.lm_hash && !nt_hash_checked)
			    || (io->o.lm_hash && memcmp(io->og.lm_hash->hash, io->o.lm_hash->hash, 16) != 0)) {
				return make_error_and_update_badPwdCount(io, werror);
			}
		}
	}

	if (io->u.restrictions == 0) {
		/* FIXME: Is this right? */
		return LDB_SUCCESS;
	}

	/* Password minimum age: yes, this is a minus. The ages are in negative 100nsec units! */
	if ((io->u.pwdLastSet - io->ac->status->domain_data.minPwdAge > io->g.last_set) &&
	    !io->ac->pwd_reset)
	{
		ret = LDB_ERR_CONSTRAINT_VIOLATION;
		*werror = WERR_PASSWORD_RESTRICTION;
		ldb_asprintf_errstring(ldb,
			"%08X: %s - check_password_restrictions: "
			"password is too young to change!",
			W_ERROR_V(*werror),
			ldb_strerror(ret));
		return ret;
	}

	/*
	 * Fundamental password checks done by the call
	 * "samdb_check_password".
	 * It is also in use by "dcesrv_samr_ValidatePassword".
	 */
	if (io->n.cleartext_utf8 != NULL) {
		enum samr_ValidationStatus vstat;
		vstat = samdb_check_password(io->ac, lp_ctx,
					     io->u.sAMAccountName,
					     io->u.user_principal_name,
					     io->u.displayName,
					     io->n.cleartext_utf8,
					     io->ac->status->domain_data.pwdProperties,
					     io->ac->status->domain_data.minPwdLength);
		switch (vstat) {
		case SAMR_VALIDATION_STATUS_SUCCESS:
				/* perfect -> proceed! */
			break;

		case SAMR_VALIDATION_STATUS_PWD_TOO_SHORT:
			ret = LDB_ERR_CONSTRAINT_VIOLATION;
			*werror = WERR_PASSWORD_RESTRICTION;
			ldb_asprintf_errstring(ldb,
				"%08X: %s - check_password_restrictions: "
				"the password is too short. It should be equal or longer than %u characters!",
				W_ERROR_V(*werror),
				ldb_strerror(ret),
				io->ac->status->domain_data.minPwdLength);
			io->ac->status->reject_reason = SAM_PWD_CHANGE_PASSWORD_TOO_SHORT;
			return ret;

		case SAMR_VALIDATION_STATUS_NOT_COMPLEX_ENOUGH:
			ret = LDB_ERR_CONSTRAINT_VIOLATION;
			*werror = WERR_PASSWORD_RESTRICTION;
			ldb_asprintf_errstring(ldb,
				"%08X: %s - check_password_restrictions: "
				"the password does not meet the complexity criteria!",
				W_ERROR_V(*werror),
				ldb_strerror(ret));
			io->ac->status->reject_reason = SAM_PWD_CHANGE_NOT_COMPLEX;
			return ret;

		default:
			ret = LDB_ERR_CONSTRAINT_VIOLATION;
			*werror = WERR_PASSWORD_RESTRICTION;
			ldb_asprintf_errstring(ldb,
				"%08X: %s - check_password_restrictions: "
				"the password doesn't fit due to a miscellaneous restriction!",
				W_ERROR_V(*werror),
				ldb_strerror(ret));
			return ret;
		}
	}

	if (io->ac->pwd_reset) {
		*werror = WERR_OK;
		return LDB_SUCCESS;
	}

	if (io->n.nt_hash) {
		uint32_t i;

		/* checks the NT hash password history */
		for (i = 0; i < io->o.nt_history_len; i++) {
			ret = memcmp(io->n.nt_hash, io->o.nt_history[i].hash, 16);
			if (ret == 0) {
				ret = LDB_ERR_CONSTRAINT_VIOLATION;
				*werror = WERR_PASSWORD_RESTRICTION;
				ldb_asprintf_errstring(ldb,
					"%08X: %s - check_password_restrictions: "
					"the password was already used (in history)!",
					W_ERROR_V(*werror),
					ldb_strerror(ret));
				io->ac->status->reject_reason = SAM_PWD_CHANGE_PWD_IN_HISTORY;
				return ret;
			}
		}
	}

	if (io->n.lm_hash) {
		uint32_t i;

		/* checks the LM hash password history */
		for (i = 0; i < io->o.lm_history_len; i++) {
			ret = memcmp(io->n.lm_hash, io->o.lm_history[i].hash, 16);
			if (ret == 0) {
				ret = LDB_ERR_CONSTRAINT_VIOLATION;
				*werror = WERR_PASSWORD_RESTRICTION;
				ldb_asprintf_errstring(ldb,
					"%08X: %s - check_password_restrictions: "
					"the password was already used (in history)!",
					W_ERROR_V(*werror),
					ldb_strerror(ret));
				io->ac->status->reject_reason = SAM_PWD_CHANGE_PWD_IN_HISTORY;
				return ret;
			}
		}
	}

	/* are all password changes disallowed? */
	if (io->ac->status->domain_data.pwdProperties & DOMAIN_REFUSE_PASSWORD_CHANGE) {
		ret = LDB_ERR_CONSTRAINT_VIOLATION;
		*werror = WERR_PASSWORD_RESTRICTION;
		ldb_asprintf_errstring(ldb,
			"%08X: %s - check_password_restrictions: "
			"password changes disabled!",
			W_ERROR_V(*werror),
			ldb_strerror(ret));
		return ret;
	}

	/* can this user change the password? */
	if (io->u.userAccountControl & UF_PASSWD_CANT_CHANGE) {
		ret = LDB_ERR_CONSTRAINT_VIOLATION;
		*werror = WERR_PASSWORD_RESTRICTION;
		ldb_asprintf_errstring(ldb,
			"%08X: %s - check_password_restrictions: "
			"password can't be changed on this account!",
			W_ERROR_V(*werror),
			ldb_strerror(ret));
		return ret;
	}

	return LDB_SUCCESS;
}

static int check_password_restrictions_and_log(struct setup_password_fields_io *io)
{
	WERROR werror;
	int ret = check_password_restrictions(io, &werror);
	struct ph_context *ac = io->ac;
	/*
	 * Password resets are not authentication events, and if the
	 * upper layer checked the password and supplied the hash
	 * values as proof, then this is also not an authentication
	 * even at this layer (already logged).  This is to log LDAP
	 * password changes.
	 */

	/* Do not record a failure in the auth log below in the success case */
	if (ret == LDB_SUCCESS) {
		werror = WERR_OK;
	}

	if (ac->pwd_reset == false && ac->change == NULL) {
		struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
		struct imessaging_context *msg_ctx;
		struct loadparm_context *lp_ctx
			= talloc_get_type_abort(ldb_get_opaque(ldb, "loadparm"),
						struct loadparm_context);
		NTSTATUS status = werror_to_ntstatus(werror);
		const char *domain_name = lpcfg_sam_name(lp_ctx);
		void *opaque_remote_address = NULL;
		/*
		 * Forcing this via the NTLM auth structure is not ideal, but
		 * it is the most practical option right now, and ensures the
		 * logs are consistent, even if some elements are always NULL.
		 */
		struct auth_usersupplied_info ui = {
			.mapped_state = true,
			.was_mapped = true,
			.client = {
				.account_name = io->u.sAMAccountName,
				.domain_name = domain_name,
			},
			.mapped = {
				.account_name = io->u.sAMAccountName,
				.domain_name = domain_name,
			},
			.service_description = "LDAP Password Change",
			.auth_description = "LDAP Modify",
			.password_type = "plaintext"
		};

		opaque_remote_address = ldb_get_opaque(ldb,
						       "remoteAddress");
		if (opaque_remote_address == NULL) {
			ldb_asprintf_errstring(ldb,
					       "Failed to obtain remote address for "
					       "the LDAP client while changing the "
					       "password");
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ui.remote_host = talloc_get_type(opaque_remote_address,
						 struct tsocket_address);

		msg_ctx = imessaging_client_init(ac, lp_ctx,
						 ldb_get_event_context(ldb));
		if (!msg_ctx) {
			ldb_asprintf_errstring(ldb,
					       "Failed to generate client messaging context in %s",
					       lpcfg_imessaging_path(ac, lp_ctx));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		log_authentication_event(msg_ctx,
					 lp_ctx,
					 NULL,
					 &ui,
					 status,
					 domain_name,
					 io->u.sAMAccountName,
					 io->u.account_sid);

	}
	return ret;
}

static int update_final_msg(struct setup_password_fields_io *io)
{
	struct ldb_context *ldb = ldb_module_get_ctx(io->ac->module);
	int ret;
	int el_flags = 0;
	bool update_password = io->ac->update_password;
	bool update_scb = io->ac->update_password;

	/*
	 * If we add a user without initial password,
	 * we need to add replication meta data for
	 * following attributes:
	 * - unicodePwd
	 * - dBCSPwd
	 * - ntPwdHistory
	 * - lmPwdHistory
	 *
	 * If we add a user with initial password or a
	 * password is changed of an existing user,
	 * we need to replace the following attributes
	 * with a forced meta data update, e.g. also
	 * when updating an empty attribute with an empty value:
	 * - unicodePwd
	 * - dBCSPwd
	 * - ntPwdHistory
	 * - lmPwdHistory
	 * - supplementalCredentials
	 */

	switch (io->ac->req->operation) {
	case LDB_ADD:
		update_password = true;
		el_flags |= DSDB_FLAG_INTERNAL_FORCE_META_DATA;
		break;
	case LDB_MODIFY:
		el_flags |= LDB_FLAG_MOD_REPLACE;
		el_flags |= DSDB_FLAG_INTERNAL_FORCE_META_DATA;
		break;
	default:
		return ldb_module_operr(io->ac->module);
	}

	if (update_password) {
		ret = ldb_msg_add_empty(io->ac->update_msg,
					"unicodePwd",
					el_flags, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		ret = ldb_msg_add_empty(io->ac->update_msg,
					"dBCSPwd",
					el_flags, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		ret = ldb_msg_add_empty(io->ac->update_msg,
					"ntPwdHistory",
					el_flags, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		ret = ldb_msg_add_empty(io->ac->update_msg,
					"lmPwdHistory",
					el_flags, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (update_scb) {
		ret = ldb_msg_add_empty(io->ac->update_msg,
					"supplementalCredentials",
					el_flags, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (io->ac->update_lastset) {
		ret = ldb_msg_add_empty(io->ac->update_msg,
					"pwdLastSet",
					el_flags, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (io->g.nt_hash != NULL) {
		ret = samdb_msg_add_hash(ldb, io->ac,
					 io->ac->update_msg,
					 "unicodePwd",
					 io->g.nt_hash);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (io->g.lm_hash != NULL) {
		ret = samdb_msg_add_hash(ldb, io->ac,
					 io->ac->update_msg,
					 "dBCSPwd",
					 io->g.lm_hash);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (io->g.nt_history_len > 0) {
		ret = samdb_msg_add_hashes(ldb, io->ac,
					   io->ac->update_msg,
					   "ntPwdHistory",
					   io->g.nt_history,
					   io->g.nt_history_len);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (io->g.lm_history_len > 0) {
		ret = samdb_msg_add_hashes(ldb, io->ac,
					   io->ac->update_msg,
					   "lmPwdHistory",
					   io->g.lm_history,
					   io->g.lm_history_len);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (io->g.supplemental.length > 0) {
		ret = ldb_msg_add_value(io->ac->update_msg,
					"supplementalCredentials",
					&io->g.supplemental, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	if (io->ac->update_lastset) {
		ret = samdb_msg_add_uint64(ldb, io->ac,
					   io->ac->update_msg,
					   "pwdLastSet",
					   io->g.last_set);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return LDB_SUCCESS;
}

/*
 * This is intended for use by the "password_hash" module since there
 * password changes can be specified through one message element with the
 * new password (to set) and another one with the old password (to unset).
 *
 * The first which sets a password (new value) can have flags
 * (LDB_FLAG_MOD_ADD, LDB_FLAG_MOD_REPLACE) but also none (on "add" operations
 * for entries). The latter (old value) has always specified
 * LDB_FLAG_MOD_DELETE.
 *
 * Returns LDB_ERR_CONSTRAINT_VIOLATION and LDB_ERR_UNWILLING_TO_PERFORM if
 * matching message elements are malformed in respect to the set/change rules.
 * Otherwise it returns LDB_SUCCESS.
 */
static int msg_find_old_and_new_pwd_val(const struct ldb_message *msg,
					const char *name,
					enum ldb_request_type operation,
					const struct ldb_val **new_val,
					const struct ldb_val **old_val)
{
	unsigned int i;

	*new_val = NULL;
	*old_val = NULL;

	if (msg == NULL) {
		return LDB_SUCCESS;
	}

	for (i = 0; i < msg->num_elements; i++) {
		if (ldb_attr_cmp(msg->elements[i].name, name) != 0) {
			continue;
		}

		if ((operation == LDB_MODIFY) &&
		    (LDB_FLAG_MOD_TYPE(msg->elements[i].flags) == LDB_FLAG_MOD_DELETE)) {
			/* 0 values are allowed */
			if (msg->elements[i].num_values == 1) {
				*old_val = &msg->elements[i].values[0];
			} else if (msg->elements[i].num_values > 1) {
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}
		} else if ((operation == LDB_MODIFY) &&
			   (LDB_FLAG_MOD_TYPE(msg->elements[i].flags) == LDB_FLAG_MOD_REPLACE)) {
			if (msg->elements[i].num_values > 0) {
				*new_val = &msg->elements[i].values[msg->elements[i].num_values - 1];
			} else {
				return LDB_ERR_UNWILLING_TO_PERFORM;
			}
		} else {
			/* Add operations and LDB_FLAG_MOD_ADD */
			if (msg->elements[i].num_values > 0) {
				*new_val = &msg->elements[i].values[msg->elements[i].num_values - 1];
			} else {
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}
		}
	}

	return LDB_SUCCESS;
}

static int setup_io(struct ph_context *ac, 
		    const struct ldb_message *client_msg,
		    const struct ldb_message *existing_msg,
		    struct setup_password_fields_io *io) 
{ 
	const struct ldb_val *quoted_utf16, *old_quoted_utf16, *lm_hash, *old_lm_hash;
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct loadparm_context *lp_ctx = talloc_get_type(
		ldb_get_opaque(ldb, "loadparm"), struct loadparm_context);
	int ret;
	const struct ldb_message *info_msg = NULL;
	struct dom_sid *account_sid = NULL;
	int rodc_krbtgt = 0;

	ZERO_STRUCTP(io);

	/* Some operations below require kerberos contexts */

	if (existing_msg != NULL) {
		/*
		 * This is a modify operation
		 */
		info_msg = existing_msg;
	} else {
		/*
		 * This is an add operation
		 */
		info_msg = client_msg;
	}

	ret = smb_krb5_init_context(ac,
				  (struct loadparm_context *)ldb_get_opaque(ldb, "loadparm"),
				  &io->smb_krb5_context);

	if (ret != 0) {
		/*
		 * In the special case of mit krb5.conf vs heimdal, the includedir
		 * statement causes ret == 22 (KRB5_CONFIG_BADFORMAT) to be returned.
		 * We look for this case so that we can give a more instructional
		 * message to the administrator.
		 */
		if (ret == KRB5_CONFIG_BADFORMAT || ret == EINVAL) {
			ldb_asprintf_errstring(ldb, "Failed to setup krb5_context: %s - "
				"This could be due to an invalid krb5 configuration. "
				"Please check your system's krb5 configuration is correct.",
				error_message(ret));
		} else {
			ldb_asprintf_errstring(ldb, "Failed to setup krb5_context: %s",
				error_message(ret));
		}
		return LDB_ERR_OPERATIONS_ERROR;
	}

	io->ac				= ac;

	io->u.userAccountControl	= ldb_msg_find_attr_as_uint(info_msg,
								    "userAccountControl", 0);
	if (info_msg == existing_msg) {
		/*
		 * We only take pwdLastSet from the existing object
		 * otherwise we leave it as 0.
		 *
		 * If no attribute is available, e.g. on deleted objects
		 * we remember that as UINT64_MAX.
		 */
		io->u.pwdLastSet = samdb_result_nttime(info_msg, "pwdLastSet",
						       UINT64_MAX);
	}
	io->u.sAMAccountName		= ldb_msg_find_attr_as_string(info_msg,
								      "sAMAccountName", NULL);
	io->u.user_principal_name	= ldb_msg_find_attr_as_string(info_msg,
								      "userPrincipalName", NULL);
	io->u.displayName		= ldb_msg_find_attr_as_string(info_msg,
								      "displayName", NULL);

	/* Ensure it has an objectSID too */
	io->u.account_sid = samdb_result_dom_sid(ac, info_msg, "objectSid");
	if (io->u.account_sid != NULL) {
		NTSTATUS status;
		uint32_t rid = 0;

		status = dom_sid_split_rid(account_sid, io->u.account_sid, NULL, &rid);
		if (NT_STATUS_IS_OK(status)) {
			if (rid == DOMAIN_RID_KRBTGT) {
				io->u.is_krbtgt = true;
			}
		}
	}

	rodc_krbtgt = ldb_msg_find_attr_as_int(info_msg,
			"msDS-SecondaryKrbTgtNumber", 0);
	if (rodc_krbtgt != 0) {
		io->u.is_krbtgt = true;
	}

	if (io->u.sAMAccountName == NULL) {
		ldb_asprintf_errstring(ldb,
				       "setup_io: sAMAccountName attribute is missing on %s for attempted password set/change",
				       ldb_dn_get_linearized(info_msg->dn));

		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	if (io->u.userAccountControl & UF_INTERDOMAIN_TRUST_ACCOUNT) {
		struct ldb_control *permit_trust = ldb_request_get_control(ac->req,
				DSDB_CONTROL_PERMIT_INTERDOMAIN_TRUST_UAC_OID);

		if (permit_trust == NULL) {
			ret = LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
			ldb_asprintf_errstring(ldb,
				"%08X: %s - setup_io: changing the interdomain trust password "
				"on %s not allowed via LDAP. Use LSA or NETLOGON",
				W_ERROR_V(WERR_ACCESS_DENIED),
				ldb_strerror(ret),
				ldb_dn_get_linearized(info_msg->dn));
			return ret;
		}
	}

	/* Only non-trust accounts have restrictions (possibly this test is the
	 * wrong way around, but we like to be restrictive if possible */
	io->u.restrictions = !(io->u.userAccountControl & UF_TRUST_ACCOUNT_MASK);

	if (io->u.is_krbtgt) {
		io->u.restrictions = 0;
		io->ac->status->domain_data.pwdHistoryLength =
			MAX(io->ac->status->domain_data.pwdHistoryLength, 3);
	}

	if (ac->userPassword) {
		ret = msg_find_old_and_new_pwd_val(client_msg, "userPassword",
						   ac->req->operation,
						   &io->n.cleartext_utf8,
						   &io->og.cleartext_utf8);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb,
				"setup_io: "
				"it's only allowed to set the old password once!");
			return ret;
		}
	}

	if (io->n.cleartext_utf8 != NULL) {
		struct ldb_val *cleartext_utf8_blob;
		char *p;

		cleartext_utf8_blob = talloc(io->ac, struct ldb_val);
		if (!cleartext_utf8_blob) {
			return ldb_oom(ldb);
		}

		*cleartext_utf8_blob = *io->n.cleartext_utf8;

		/* make sure we have a null terminated string */
		p = talloc_strndup(cleartext_utf8_blob,
				   (const char *)io->n.cleartext_utf8->data,
				   io->n.cleartext_utf8->length);
		if ((p == NULL) && (io->n.cleartext_utf8->length > 0)) {
			return ldb_oom(ldb);
		}
		cleartext_utf8_blob->data = (uint8_t *)p;

		io->n.cleartext_utf8 = cleartext_utf8_blob;
	}

	ret = msg_find_old_and_new_pwd_val(client_msg, "clearTextPassword",
					   ac->req->operation,
					   &io->n.cleartext_utf16,
					   &io->og.cleartext_utf16);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb,
			"setup_io: "
			"it's only allowed to set the old password once!");
		return ret;
	}

	/* this rather strange looking piece of code is there to
	   handle a ldap client setting a password remotely using the
	   unicodePwd ldap field. The syntax is that the password is
	   in UTF-16LE, with a " at either end. Unfortunately the
	   unicodePwd field is also used to store the nt hashes
	   internally in Samba, and is used in the nt hash format on
	   the wire in DRS replication, so we have a single name for
	   two distinct values. The code below leaves us with a small
	   chance (less than 1 in 2^32) of a mixup, if someone manages
	   to create a MD4 hash which starts and ends in 0x22 0x00, as
	   that would then be treated as a UTF16 password rather than
	   a nthash */

	ret = msg_find_old_and_new_pwd_val(client_msg, "unicodePwd",
					   ac->req->operation,
					   &quoted_utf16,
					   &old_quoted_utf16);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb,
			"setup_io: "
			"it's only allowed to set the old password once!");
		return ret;
	}

	/* Checks and converts the actual "unicodePwd" attribute */
	if (!ac->hash_values &&
	    quoted_utf16 &&
	    quoted_utf16->length >= 4 &&
	    quoted_utf16->data[0] == '"' &&
	    quoted_utf16->data[1] == 0 &&
	    quoted_utf16->data[quoted_utf16->length-2] == '"' &&
	    quoted_utf16->data[quoted_utf16->length-1] == 0) {
		struct ldb_val *quoted_utf16_2;

		if (io->n.cleartext_utf16) {
			/* refuse the change if someone wants to change with
			   with both UTF16 possibilities at the same time... */
			ldb_asprintf_errstring(ldb,
				"setup_io: "
				"it's only allowed to set the cleartext password as 'unicodePwd' or as 'clearTextPassword'");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		/*
		 * adapt the quoted UTF16 string to be a real
		 * cleartext one
		 */
		quoted_utf16_2 = talloc(io->ac, struct ldb_val);
		if (quoted_utf16_2 == NULL) {
			return ldb_oom(ldb);
		}

		quoted_utf16_2->data = quoted_utf16->data + 2;
		quoted_utf16_2->length = quoted_utf16->length-4;
		io->n.cleartext_utf16 = quoted_utf16_2;
		io->n.nt_hash = NULL;

	} else if (quoted_utf16) {
		/* We have only the hash available -> so no plaintext here */
		if (!ac->hash_values) {
			/* refuse the change if someone wants to change
			   the hash without control specified... */
			ldb_asprintf_errstring(ldb,
				"setup_io: "
				"it's not allowed to set the NT hash password directly'");
			/* this looks odd but this is what Windows does:
			   returns "UNWILLING_TO_PERFORM" on wrong
			   password sets and "CONSTRAINT_VIOLATION" on
			   wrong password changes. */
			if (old_quoted_utf16 == NULL) {
				return LDB_ERR_UNWILLING_TO_PERFORM;
			}

			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		io->n.nt_hash = talloc(io->ac, struct samr_Password);
		memcpy(io->n.nt_hash->hash, quoted_utf16->data,
		       MIN(quoted_utf16->length, sizeof(io->n.nt_hash->hash)));
	}

	/* Checks and converts the previous "unicodePwd" attribute */
	if (!ac->hash_values &&
	    old_quoted_utf16 &&
	    old_quoted_utf16->length >= 4 &&
	    old_quoted_utf16->data[0] == '"' &&
	    old_quoted_utf16->data[1] == 0 &&
	    old_quoted_utf16->data[old_quoted_utf16->length-2] == '"' &&
	    old_quoted_utf16->data[old_quoted_utf16->length-1] == 0) {
		struct ldb_val *old_quoted_utf16_2;

		if (io->og.cleartext_utf16) {
			/* refuse the change if someone wants to change with
			   both UTF16 possibilities at the same time... */
			ldb_asprintf_errstring(ldb,
				"setup_io: "
				"it's only allowed to set the cleartext password as 'unicodePwd' or as 'clearTextPassword'");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		/*
		 * adapt the quoted UTF16 string to be a real
		 * cleartext one
		 */
		old_quoted_utf16_2 = talloc(io->ac, struct ldb_val);
		if (old_quoted_utf16_2 == NULL) {
			return ldb_oom(ldb);
		}

		old_quoted_utf16_2->data = old_quoted_utf16->data + 2;
		old_quoted_utf16_2->length = old_quoted_utf16->length-4;

		io->og.cleartext_utf16 = old_quoted_utf16_2;
		io->og.nt_hash = NULL;
	} else if (old_quoted_utf16) {
		/* We have only the hash available -> so no plaintext here */
		if (!ac->hash_values) {
			/* refuse the change if someone wants to change
			   the hash without control specified... */
			ldb_asprintf_errstring(ldb,
				"setup_io: "
				"it's not allowed to set the NT hash password directly'");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		io->og.nt_hash = talloc(io->ac, struct samr_Password);
		memcpy(io->og.nt_hash->hash, old_quoted_utf16->data,
		       MIN(old_quoted_utf16->length, sizeof(io->og.nt_hash->hash)));
	}

	/* Handles the "dBCSPwd" attribute (LM hash) */
	io->n.lm_hash = NULL; io->og.lm_hash = NULL;
	ret = msg_find_old_and_new_pwd_val(client_msg, "dBCSPwd",
					   ac->req->operation,
					   &lm_hash, &old_lm_hash);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb,
			"setup_io: "
			"it's only allowed to set the old password once!");
		return ret;
	}

	if (((lm_hash != NULL) || (old_lm_hash != NULL)) && (!ac->hash_values)) {
		/* refuse the change if someone wants to change the hash
		   without control specified... */
		ldb_asprintf_errstring(ldb,
			"setup_io: "
			"it's not allowed to set the LM hash password directly'");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	if (lpcfg_lanman_auth(lp_ctx) && (lm_hash != NULL)) {
		io->n.lm_hash = talloc(io->ac, struct samr_Password);
		memcpy(io->n.lm_hash->hash, lm_hash->data, MIN(lm_hash->length,
		       sizeof(io->n.lm_hash->hash)));
	}
	if (lpcfg_lanman_auth(lp_ctx) && (old_lm_hash != NULL)) {
		io->og.lm_hash = talloc(io->ac, struct samr_Password);
		memcpy(io->og.lm_hash->hash, old_lm_hash->data, MIN(old_lm_hash->length,
		       sizeof(io->og.lm_hash->hash)));
	}

	/*
	 * Handles the password change control if it's specified. It has the
	 * precedance and overrides already specified old password values of
	 * change requests (but that shouldn't happen since the control is
	 * fully internal and only used in conjunction with replace requests!).
	 */
	if (ac->change != NULL) {
		io->og.nt_hash = NULL;
		if (ac->change->old_nt_pwd_hash != NULL) {
			io->og.nt_hash = talloc_memdup(io->ac,
						       ac->change->old_nt_pwd_hash,
						       sizeof(struct samr_Password));
		}
		io->og.lm_hash = NULL;
		if (lpcfg_lanman_auth(lp_ctx) && (ac->change->old_lm_pwd_hash != NULL)) {
			io->og.lm_hash = talloc_memdup(io->ac,
						       ac->change->old_lm_pwd_hash,
						       sizeof(struct samr_Password));
		}
	}

	/* refuse the change if someone wants to change the clear-
	   text and supply his own hashes at the same time... */
	if ((io->n.cleartext_utf8 || io->n.cleartext_utf16)
			&& (io->n.nt_hash || io->n.lm_hash)) {
		ldb_asprintf_errstring(ldb,
			"setup_io: "
			"it's only allowed to set the password in form of cleartext attributes or as hashes");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* refuse the change if someone wants to change the password
	   using both plaintext methods (UTF8 and UTF16) at the same time... */
	if (io->n.cleartext_utf8 && io->n.cleartext_utf16) {
		ldb_asprintf_errstring(ldb,
			"setup_io: "
			"it's only allowed to set the cleartext password as 'unicodePwd' or as 'userPassword' or as 'clearTextPassword'");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* refuse the change if someone tries to set/change the password by
	 * the lanman hash alone and we've deactivated that mechanism. This
	 * would end in an account without any password! */
	if (io->ac->update_password
	    && (!io->n.cleartext_utf8) && (!io->n.cleartext_utf16)
	    && (!io->n.nt_hash) && (!io->n.lm_hash)) {
		ldb_asprintf_errstring(ldb,
			"setup_io: "
			"It's not possible to delete the password (changes using the LAN Manager hash alone could be deactivated)!");
		/* on "userPassword" and "clearTextPassword" we've to return
		 * something different, since these are virtual attributes */
		if ((ldb_msg_find_element(client_msg, "userPassword") != NULL) ||
		    (ldb_msg_find_element(client_msg, "clearTextPassword") != NULL)) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* refuse the change if someone wants to compare against a plaintext
	   or hash at the same time for a "password modify" operation... */
	if ((io->og.cleartext_utf8 || io->og.cleartext_utf16)
	    && (io->og.nt_hash || io->og.lm_hash)) {
		ldb_asprintf_errstring(ldb,
			"setup_io: "
			"it's only allowed to provide the old password in form of cleartext attributes or as hashes");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* refuse the change if someone wants to compare against both
	 * plaintexts at the same time for a "password modify" operation... */
	if (io->og.cleartext_utf8 && io->og.cleartext_utf16) {
		ldb_asprintf_errstring(ldb,
			"setup_io: "
			"it's only allowed to provide the old cleartext password as 'unicodePwd' or as 'userPassword' or as 'clearTextPassword'");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* Decides if we have a password modify or password reset operation */
	if (ac->req->operation == LDB_ADD) {
		/* On "add" we have only "password reset" */
		ac->pwd_reset = true;
	} else if (ac->req->operation == LDB_MODIFY) {
		struct ldb_control *pav_ctrl = NULL;
		struct dsdb_control_password_acl_validation *pav = NULL;

		pav_ctrl = ldb_request_get_control(ac->req,
				DSDB_CONTROL_PASSWORD_ACL_VALIDATION_OID);
		if (pav_ctrl != NULL) {
			pav = talloc_get_type_abort(pav_ctrl->data,
				struct dsdb_control_password_acl_validation);
		}

		if (pav == NULL && ac->update_password) {
			bool ok;

			/*
			 * If the DSDB_CONTROL_PASSWORD_ACL_VALIDATION_OID
			 * control is missing, we require system access!
			 */
			ok = dsdb_module_am_system(ac->module);
			if (!ok) {
				return ldb_module_operr(ac->module);
			}
		}

		if (pav != NULL) {
			/*
			 * We assume what the acl module has validated.
			 */
			ac->pwd_reset = pav->pwd_reset;
		} else if (io->og.cleartext_utf8 || io->og.cleartext_utf16
		    || io->og.nt_hash || io->og.lm_hash) {
			/* If we have an old password specified then for sure it
			 * is a user "password change" */
			ac->pwd_reset = false;
		} else {
			/* Otherwise we have also here a "password reset" */
			ac->pwd_reset = true;
		}
	} else {
		/* this shouldn't happen */
		return ldb_operr(ldb);
	}

	if (io->u.is_krbtgt) {
		size_t min = 196;
		size_t max = 255;
		size_t diff = max - min;
		size_t len = max;
		struct ldb_val *krbtgt_utf16 = NULL;

		if (!ac->pwd_reset) {
			return dsdb_module_werror(ac->module,
					LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS,
					WERR_DS_ATT_ALREADY_EXISTS,
					"Password change on krbtgt not permitted!");
		}

		if (io->n.cleartext_utf16 == NULL) {
			return dsdb_module_werror(ac->module,
					LDB_ERR_UNWILLING_TO_PERFORM,
					WERR_DS_INVALID_ATTRIBUTE_SYNTAX,
					"Password reset on krbtgt requires UTF16!");
		}

		/*
		 * Instead of taking the callers value,
		 * we just generate a new random value here.
		 *
		 * Include null termination in the array.
		 */
		if (diff > 0) {
			size_t tmp;

			generate_random_buffer((uint8_t *)&tmp, sizeof(tmp));

			tmp %= diff;

			len = min + tmp;
		}

		krbtgt_utf16 = talloc_zero(io->ac, struct ldb_val);
		if (krbtgt_utf16 == NULL) {
			return ldb_oom(ldb);
		}

		*krbtgt_utf16 = data_blob_talloc_zero(krbtgt_utf16,
						      (len+1)*2);
		if (krbtgt_utf16->data == NULL) {
			return ldb_oom(ldb);
		}
		krbtgt_utf16->length = len * 2;
		generate_secret_buffer(krbtgt_utf16->data,
				       krbtgt_utf16->length);
		io->n.cleartext_utf16 = krbtgt_utf16;
	}

	if (existing_msg != NULL) {
		NTSTATUS status;

		if (ac->pwd_reset) {
			/* Get the old password from the database */
			status = samdb_result_passwords_no_lockout(ac,
								   lp_ctx,
								   existing_msg,
								   &io->o.lm_hash,
								   &io->o.nt_hash);
		} else {
			/* Get the old password from the database */
			status = samdb_result_passwords(ac,
							lp_ctx,
							existing_msg,
							&io->o.lm_hash,
							&io->o.nt_hash);
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCOUNT_LOCKED_OUT)) {
			return dsdb_module_werror(ac->module,
						  LDB_ERR_CONSTRAINT_VIOLATION,
						  WERR_ACCOUNT_LOCKED_OUT,
						  "Password change not permitted,"
						  " account locked out!");
		}

		if (!NT_STATUS_IS_OK(status)) {
			/*
			 * This only happens if the database has gone weird,
			 * not if we are just missing the passwords
			 */
			return ldb_operr(ldb);
		}

		io->o.nt_history_len = samdb_result_hashes(ac, existing_msg,
							   "ntPwdHistory",
							   &io->o.nt_history);
		io->o.lm_history_len = samdb_result_hashes(ac, existing_msg,
							   "lmPwdHistory",
							   &io->o.lm_history);
		io->o.supplemental = ldb_msg_find_ldb_val(existing_msg,
							  "supplementalCredentials");

		if (io->o.supplemental != NULL) {
			enum ndr_err_code ndr_err;

			ndr_err = ndr_pull_struct_blob_all(io->o.supplemental, io->ac,
					&io->o.scb,
					(ndr_pull_flags_fn_t)ndr_pull_supplementalCredentialsBlob);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				status = ndr_map_error2ntstatus(ndr_err);
				ldb_asprintf_errstring(ldb,
						"setup_io: failed to pull "
						"old supplementalCredentialsBlob: %s",
						nt_errstr(status));
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}
	}

	return LDB_SUCCESS;
}

static struct ph_context *ph_init_context(struct ldb_module *module,
					  struct ldb_request *req,
					  bool userPassword,
					  bool update_password)
{
	struct ldb_context *ldb;
	struct ph_context *ac;
	struct loadparm_context *lp_ctx = NULL;

	ldb = ldb_module_get_ctx(module);

	ac = talloc_zero(req, struct ph_context);
	if (ac == NULL) {
		ldb_set_errstring(ldb, "Out of Memory");
		return NULL;
	}

	ac->module = module;
	ac->req = req;
	ac->userPassword = userPassword;
	ac->update_password = update_password;
	ac->update_lastset = true;

	lp_ctx = talloc_get_type_abort(ldb_get_opaque(ldb, "loadparm"),
				       struct loadparm_context);
	ac->gpg_key_ids = lpcfg_password_hash_gpg_key_ids(lp_ctx);
	ac->userPassword_schemes
		= lpcfg_password_hash_userpassword_schemes(lp_ctx);
	return ac;
}

static void ph_apply_controls(struct ph_context *ac)
{
	struct ldb_control *ctrl;

	ac->change_status = false;
	ctrl = ldb_request_get_control(ac->req,
				       DSDB_CONTROL_PASSWORD_CHANGE_STATUS_OID);
	if (ctrl != NULL) {
		ac->change_status = true;

		/* Mark the "change status" control as uncritical (done) */
		ctrl->critical = false;
	}

	ac->hash_values = false;
	ctrl = ldb_request_get_control(ac->req,
				       DSDB_CONTROL_PASSWORD_HASH_VALUES_OID);
	if (ctrl != NULL) {
		ac->hash_values = true;

		/* Mark the "hash values" control as uncritical (done) */
		ctrl->critical = false;
	}

	ctrl = ldb_request_get_control(ac->req,
				       DSDB_CONTROL_PASSWORD_CHANGE_OID);
	if (ctrl != NULL) {
		ac->change = (struct dsdb_control_password_change *) ctrl->data;

		/* Mark the "change" control as uncritical (done) */
		ctrl->critical = false;
	}

	ac->pwd_last_set_bypass = false;
	ctrl = ldb_request_get_control(ac->req,
				DSDB_CONTROL_PASSWORD_BYPASS_LAST_SET_OID);
	if (ctrl != NULL) {
		ac->pwd_last_set_bypass = true;

		/* Mark the "bypass pwdLastSet" control as uncritical (done) */
		ctrl->critical = false;
	}

	ac->pwd_last_set_default = false;
	ctrl = ldb_request_get_control(ac->req,
				DSDB_CONTROL_PASSWORD_DEFAULT_LAST_SET_OID);
	if (ctrl != NULL) {
		ac->pwd_last_set_default = true;

		/* Mark the "bypass pwdLastSet" control as uncritical (done) */
		ctrl->critical = false;
	}

	ac->smartcard_reset = false;
	ctrl = ldb_request_get_control(ac->req,
				DSDB_CONTROL_PASSWORD_USER_ACCOUNT_CONTROL_OID);
	if (ctrl != NULL) {
		struct dsdb_control_password_user_account_control *uac = NULL;
		uint32_t added_flags = 0;

		uac = talloc_get_type_abort(ctrl->data,
			struct dsdb_control_password_user_account_control);

		added_flags = uac->new_flags & ~uac->old_flags;

		if (added_flags & UF_SMARTCARD_REQUIRED) {
			ac->smartcard_reset = true;
		}

		/* Mark the "smartcard required" control as uncritical (done) */
		ctrl->critical = false;
	}
}

static int ph_op_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ph_context *ac;

	ac = talloc_get_type(req->context, struct ph_context);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	if (ares->type == LDB_REPLY_REFERRAL) {
		return ldb_module_send_referral(ac->req, ares->referral);
	}

	if ((ares->error != LDB_ERR_OPERATIONS_ERROR) && (ac->change_status)) {
		/* On success and trivial errors a status control is being
		 * added (used for example by the "samdb_set_password" call) */
		ldb_reply_add_control(ares,
				      DSDB_CONTROL_PASSWORD_CHANGE_STATUS_OID,
				      false,
				      ac->status);
	}

	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	return ldb_module_done(ac->req, ares->controls,
				ares->response, ares->error);
}

static int password_hash_add_do_add(struct ph_context *ac);
static int ph_modify_callback(struct ldb_request *req, struct ldb_reply *ares);
static int password_hash_mod_search_self(struct ph_context *ac);
static int ph_mod_search_callback(struct ldb_request *req, struct ldb_reply *ares);
static int password_hash_mod_do_mod(struct ph_context *ac);

/*
 * LDB callback handler for searching for a user's PSO. Once we have all the
 * Password Settings that apply to the user, we can continue with the modify
 * operation
 */
static int get_pso_data_callback(struct ldb_request *req,
				 struct ldb_reply *ares)
{
	struct ldb_context *ldb = NULL;
	struct ph_context *ac = NULL;
	bool domain_complexity = true;
	bool pso_complexity = true;
	struct dsdb_user_pwd_settings *settings = NULL;
	int ret = LDB_SUCCESS;

	ac = talloc_get_type(req->context, struct ph_context);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
				       ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:

		/* check status was initialized by the domain query */
		if (ac->status == NULL) {
			talloc_free(ares);
			ldb_set_errstring(ldb, "Uninitialized status");
			ret = LDB_ERR_OPERATIONS_ERROR;
			goto done;
		}

		/*
		 * use the PSO's values instead of the domain defaults (the PSO
		 * attributes should always exist, but use the domain default
		 * values as a fallback).
		 */
		settings = &ac->status->domain_data;
		settings->store_cleartext =
			ldb_msg_find_attr_as_bool(ares->message,
						  "msDS-PasswordReversibleEncryptionEnabled",
						  settings->store_cleartext);

		settings->pwdHistoryLength =
			ldb_msg_find_attr_as_uint(ares->message,
						  "msDS-PasswordHistoryLength",
						  settings->pwdHistoryLength);
		settings->maxPwdAge =
			ldb_msg_find_attr_as_int64(ares->message,
						   "msDS-MaximumPasswordAge",
						   settings->maxPwdAge);
		settings->minPwdAge =
			ldb_msg_find_attr_as_int64(ares->message,
						   "msDS-MinimumPasswordAge",
						   settings->minPwdAge);
		settings->minPwdLength =
			ldb_msg_find_attr_as_uint(ares->message,
						  "msDS-MinimumPasswordLength",
						  settings->minPwdLength);
		domain_complexity =
			(settings->pwdProperties & DOMAIN_PASSWORD_COMPLEX);
		pso_complexity =
			ldb_msg_find_attr_as_bool(ares->message,
						  "msDS-PasswordComplexityEnabled",
						   domain_complexity);

		/* set or clear the complexity bit if required */
		if (pso_complexity && !domain_complexity) {
			settings->pwdProperties |= DOMAIN_PASSWORD_COMPLEX;
		} else if (domain_complexity && !pso_complexity) {
			settings->pwdProperties &= ~DOMAIN_PASSWORD_COMPLEX;
		}

		if (ac->pso_res != NULL) {
			DBG_ERR("Too many PSO results for %s",
				ldb_dn_get_linearized(ac->search_res->message->dn));
			talloc_free(ac->pso_res);
		}

		/* store the PSO result (we may need its lockout settings) */
		ac->pso_res = talloc_steal(ac, ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_DONE:
		talloc_free(ares);

		/*
		 * perform the next step of the modify operation (this code
		 * shouldn't get called in the 'user add' case)
		 */
		if (ac->req->operation == LDB_MODIFY) {
			ret = password_hash_mod_do_mod(ac);
		} else {
			ret = LDB_ERR_OPERATIONS_ERROR;
		}
		break;
	}

done:
	if (ret != LDB_SUCCESS) {
		struct ldb_reply *new_ares;

		new_ares = talloc_zero(ac->req, struct ldb_reply);
		if (new_ares == NULL) {
			ldb_oom(ldb);
			return ldb_module_done(ac->req, NULL, NULL,
					       LDB_ERR_OPERATIONS_ERROR);
		}

		new_ares->error = ret;
		if ((ret != LDB_ERR_OPERATIONS_ERROR) && (ac->change_status)) {
			/* On success and trivial errors a status control is being
			 * added (used for example by the "samdb_set_password" call) */
			ldb_reply_add_control(new_ares,
					      DSDB_CONTROL_PASSWORD_CHANGE_STATUS_OID,
					      false,
					      ac->status);
		}

		return ldb_module_done(ac->req, new_ares->controls,
				       new_ares->response, new_ares->error);
	}

	return LDB_SUCCESS;
}

/*
 * Builds and returns a search request to lookup up the PSO that applies to
 * the user in question. Returns NULL if no PSO applies, or could not be found
 */
static struct ldb_request * build_pso_data_request(struct ph_context *ac)
{
	/* attrs[] is returned from this function in
	   pso_req->op.search.attrs, so it must be static, as
	   otherwise the compiler can put it on the stack */
	static const char * const attrs[] = { "msDS-PasswordComplexityEnabled",
					      "msDS-PasswordReversibleEncryptionEnabled",
					      "msDS-PasswordHistoryLength",
					      "msDS-MaximumPasswordAge",
					      "msDS-MinimumPasswordAge",
					      "msDS-MinimumPasswordLength",
					      "msDS-LockoutThreshold",
					      "msDS-LockoutObservationWindow",
					      NULL };
	struct ldb_context *ldb = NULL;
	struct ldb_request *pso_req = NULL;
	struct ldb_dn *pso_dn = NULL;
	TALLOC_CTX *mem_ctx = ac;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	/* if a PSO applies to the user, we need to lookup the PSO as well */
	pso_dn = ldb_msg_find_attr_as_dn(ldb, mem_ctx, ac->search_res->message,
					 "msDS-ResultantPSO");
	if (pso_dn == NULL) {
		return NULL;
	}

	ret = ldb_build_search_req(&pso_req, ldb, mem_ctx, pso_dn,
				   LDB_SCOPE_BASE, NULL, attrs, NULL,
				   ac, get_pso_data_callback,
				   ac->dom_req);

	/* log errors, but continue with the default domain settings */
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Error %d constructing PSO query for user %s", ret,
			ldb_dn_get_linearized(ac->search_res->message->dn));
	}
	LDB_REQ_SET_LOCATION(pso_req);
	return pso_req;
}


static int get_domain_data_callback(struct ldb_request *req,
				    struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct ph_context *ac;
	struct loadparm_context *lp_ctx;
	struct ldb_request *pso_req = NULL;
	int ret = LDB_SUCCESS;

	ac = talloc_get_type(req->context, struct ph_context);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		if (ac->status != NULL) {
			talloc_free(ares);

			ldb_set_errstring(ldb, "Too many results");
			ret = LDB_ERR_OPERATIONS_ERROR;
			goto done;
		}

		/* Setup the "status" structure (used as control later) */
		ac->status = talloc_zero(ac->req,
					 struct dsdb_control_password_change_status);
		if (ac->status == NULL) {
			talloc_free(ares);

			ldb_oom(ldb);
			ret = LDB_ERR_OPERATIONS_ERROR;
			goto done;
		}

		/* Setup the "domain data" structure */
		ac->status->domain_data.pwdProperties =
			ldb_msg_find_attr_as_uint(ares->message, "pwdProperties", -1);
		ac->status->domain_data.pwdHistoryLength =
			ldb_msg_find_attr_as_uint(ares->message, "pwdHistoryLength", -1);
		ac->status->domain_data.maxPwdAge =
			ldb_msg_find_attr_as_int64(ares->message, "maxPwdAge", -1);
		ac->status->domain_data.minPwdAge =
			ldb_msg_find_attr_as_int64(ares->message, "minPwdAge", -1);
		ac->status->domain_data.minPwdLength =
			ldb_msg_find_attr_as_uint(ares->message, "minPwdLength", -1);
		ac->status->domain_data.store_cleartext =
			ac->status->domain_data.pwdProperties & DOMAIN_PASSWORD_STORE_CLEARTEXT;

		/* For a domain DN, this puts things in dotted notation */
		/* For builtin domains, this will give details for the host,
		 * but that doesn't really matter, as it's just used for salt
		 * and kerberos principals, which don't exist here */

		lp_ctx = talloc_get_type(ldb_get_opaque(ldb, "loadparm"),
					 struct loadparm_context);

		ac->status->domain_data.dns_domain = lpcfg_dnsdomain(lp_ctx);
		ac->status->domain_data.realm = lpcfg_realm(lp_ctx);
		ac->status->domain_data.netbios_domain = lpcfg_sam_name(lp_ctx);

		ac->status->reject_reason = SAM_PWD_CHANGE_NO_ERROR;

		if (ac->dom_res != NULL) {
			talloc_free(ares);

			ldb_set_errstring(ldb, "Too many results");
			ret = LDB_ERR_OPERATIONS_ERROR;
			goto done;
		}

		ac->dom_res = talloc_steal(ac, ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_DONE:
		talloc_free(ares);
		/* call the next step */
		switch (ac->req->operation) {
		case LDB_ADD:
			ret = password_hash_add_do_add(ac);
			break;

		case LDB_MODIFY:

			/*
			 * The user may have an optional PSO applied. If so,
			 * query the PSO to get the Fine-Grained Password Policy
			 * for the user, before we perform the modify
			 */
			pso_req = build_pso_data_request(ac);
			if (pso_req != NULL) {
				ret = ldb_next_request(ac->module, pso_req);
			} else {

				/* no PSO, so we can perform the modify now */
				ret = password_hash_mod_do_mod(ac);
			}
			break;

		default:
			ret = LDB_ERR_OPERATIONS_ERROR;
			break;
		}
		break;
	}

done:
	if (ret != LDB_SUCCESS) {
		struct ldb_reply *new_ares;

		new_ares = talloc_zero(ac->req, struct ldb_reply);
		if (new_ares == NULL) {
			ldb_oom(ldb);
			return ldb_module_done(ac->req, NULL, NULL,
					       LDB_ERR_OPERATIONS_ERROR);
		}

		new_ares->error = ret;
		if ((ret != LDB_ERR_OPERATIONS_ERROR) && (ac->change_status)) {
			/* On success and trivial errors a status control is being
			 * added (used for example by the "samdb_set_password" call) */
			ldb_reply_add_control(new_ares,
					      DSDB_CONTROL_PASSWORD_CHANGE_STATUS_OID,
					      false,
					      ac->status);
		}

		return ldb_module_done(ac->req, new_ares->controls,
				       new_ares->response, new_ares->error);
	}

	return LDB_SUCCESS;
}

static int build_domain_data_request(struct ph_context *ac)
{
	/* attrs[] is returned from this function in
	   ac->dom_req->op.search.attrs, so it must be static, as
	   otherwise the compiler can put it on the stack */
	struct ldb_context *ldb;
	static const char * const attrs[] = { "pwdProperties",
					      "pwdHistoryLength",
					      "maxPwdAge",
					      "minPwdAge",
					      "minPwdLength",
					      "lockoutThreshold",
					      "lockOutObservationWindow",
					      NULL };
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	ret = ldb_build_search_req(&ac->dom_req, ldb, ac,
				   ldb_get_default_basedn(ldb),
				   LDB_SCOPE_BASE,
				   NULL, attrs,
				   NULL,
				   ac, get_domain_data_callback,
				   ac->req);
	LDB_REQ_SET_LOCATION(ac->dom_req);
	return ret;
}

static int password_hash_needed(struct ldb_module *module,
				struct ldb_request *req,
				struct ph_context **_ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const char *operation = NULL;
	const struct ldb_message *msg = NULL;
	struct ph_context *ac = NULL;
	const char *passwordAttrs[] = {
		DSDB_PASSWORD_ATTRIBUTES,
		NULL
	};
	const char **a = NULL;
	unsigned int attr_cnt = 0;
	struct ldb_control *bypass = NULL;
	struct ldb_control *uac_ctrl = NULL;
	bool userPassword = dsdb_user_password_support(module, req, req);
	bool update_password = false;
	bool processing_needed = false;

	*_ac = NULL;

	ldb_debug(ldb, LDB_DEBUG_TRACE, "password_hash_needed\n");

	switch (req->operation) {
	case LDB_ADD:
		operation = "add";
		msg = req->op.add.message;
		break;
	case LDB_MODIFY:
		operation = "modify";
		msg = req->op.mod.message;
		break;
	default:
		return ldb_next_request(module, req);
	}

	if (ldb_dn_is_special(msg->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	bypass = ldb_request_get_control(req,
					 DSDB_CONTROL_BYPASS_PASSWORD_HASH_OID);
	if (bypass != NULL) {
		/* Mark the "bypass" control as uncritical (done) */
		bypass->critical = false;
		ldb_debug(ldb, LDB_DEBUG_TRACE,
			  "password_hash_needed(%s) (bypassing)\n",
			  operation);
		return password_hash_bypass(module, req);
	}

	/* nobody must touch password histories and 'supplementalCredentials' */
	if (ldb_msg_find_element(msg, "ntPwdHistory")) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	if (ldb_msg_find_element(msg, "lmPwdHistory")) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	if (ldb_msg_find_element(msg, "supplementalCredentials")) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/*
	 * If no part of this touches the 'userPassword' OR 'clearTextPassword'
	 * OR 'unicodePwd' OR 'dBCSPwd' we don't need to make any changes.
	 * For password changes/set there should be a 'delete' or a 'modify'
	 * on these attributes.
	 */
	for (a = passwordAttrs; *a != NULL; a++) {
		if ((!userPassword) && (ldb_attr_cmp(*a, "userPassword") == 0)) {
			continue;
		}

		if (ldb_msg_find_element(msg, *a) != NULL) {
			/* MS-ADTS 3.1.1.3.1.5.2 */
			if ((ldb_attr_cmp(*a, "userPassword") == 0) &&
			    (dsdb_functional_level(ldb) < DS_DOMAIN_FUNCTION_2003)) {
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}

			++attr_cnt;
		}
	}

	if (attr_cnt > 0) {
		update_password = true;
		processing_needed = true;
	}

	if (ldb_msg_find_element(msg, "pwdLastSet")) {
		processing_needed = true;
	}

	uac_ctrl = ldb_request_get_control(req,
				DSDB_CONTROL_PASSWORD_USER_ACCOUNT_CONTROL_OID);
	if (uac_ctrl != NULL) {
		struct dsdb_control_password_user_account_control *uac = NULL;
		uint32_t added_flags = 0;

		uac = talloc_get_type_abort(uac_ctrl->data,
			struct dsdb_control_password_user_account_control);

		added_flags = uac->new_flags & ~uac->old_flags;

		if (added_flags & UF_SMARTCARD_REQUIRED) {
			processing_needed = true;
		}
	}

	if (!processing_needed) {
		return ldb_next_request(module, req);
	}

	ac = ph_init_context(module, req, userPassword, update_password);
	if (!ac) {
		DEBUG(0,(__location__ ": %s\n", ldb_errstring(ldb)));
		return ldb_operr(ldb);
	}
	ph_apply_controls(ac);

	/*
	 * Make a copy in order to apply our modifications
	 * to the final update
	 */
	ac->update_msg = ldb_msg_copy_shallow(ac, msg);
	if (ac->update_msg == NULL) {
		return ldb_oom(ldb);
	}

	/*
	 * Remove all password related attributes.
	 */
	if (ac->userPassword) {
		ldb_msg_remove_attr(ac->update_msg, "userPassword");
	}
	ldb_msg_remove_attr(ac->update_msg, "clearTextPassword");
	ldb_msg_remove_attr(ac->update_msg, "unicodePwd");
	ldb_msg_remove_attr(ac->update_msg, "ntPwdHistory");
	ldb_msg_remove_attr(ac->update_msg, "dBCSPwd");
	ldb_msg_remove_attr(ac->update_msg, "lmPwdHistory");
	ldb_msg_remove_attr(ac->update_msg, "supplementalCredentials");
	ldb_msg_remove_attr(ac->update_msg, "pwdLastSet");

	*_ac = ac;
	return LDB_SUCCESS;
}

static int password_hash_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ph_context *ac = NULL;
	int ret;

	ldb_debug(ldb, LDB_DEBUG_TRACE, "password_hash_add\n");

	ret = password_hash_needed(module, req, &ac);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (ac == NULL) {
		return ret;
	}

	/* Make sure we are performing the password set action on a (for us)
	 * valid object. Those are instances of either "user" and/or
	 * "inetOrgPerson". Otherwise continue with the submodules. */
	if ((!ldb_msg_check_string_attribute(req->op.add.message, "objectClass", "user"))
		&& (!ldb_msg_check_string_attribute(req->op.add.message, "objectClass", "inetOrgPerson"))) {

		TALLOC_FREE(ac);

		if (ldb_msg_find_element(req->op.add.message, "clearTextPassword") != NULL) {
			ldb_set_errstring(ldb,
					  "'clearTextPassword' is only allowed on objects of class 'user' and/or 'inetOrgPerson'!");
			return LDB_ERR_NO_SUCH_ATTRIBUTE;
		}

		return ldb_next_request(module, req);
	}

	/* get user domain data */
	ret = build_domain_data_request(ac);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(module, ac->dom_req);
}

static int password_hash_add_do_add(struct ph_context *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct ldb_request *down_req;
	struct setup_password_fields_io io;
	int ret;

	/* Prepare the internal data structure containing the passwords */
	ret = setup_io(ac, ac->req->op.add.message, NULL, &io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = setup_password_fields(&io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = check_password_restrictions_and_log(&io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = setup_smartcard_reset(&io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = update_final_msg(&io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_build_add_req(&down_req, ldb, ac,
				ac->update_msg,
				ac->req->controls,
				ac, ph_op_callback,
				ac->req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, down_req);
}

static int password_hash_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ph_context *ac = NULL;
	const char *passwordAttrs[] = {DSDB_PASSWORD_ATTRIBUTES, NULL}, **l;
	unsigned int del_attr_cnt, add_attr_cnt, rep_attr_cnt;
	struct ldb_message_element *passwordAttr;
	struct ldb_message *msg;
	struct ldb_request *down_req;
	struct ldb_control *restore = NULL;
	int ret;
	unsigned int i = 0;

	ldb_debug(ldb, LDB_DEBUG_TRACE, "password_hash_modify\n");

	ret = password_hash_needed(module, req, &ac);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (ac == NULL) {
		return ret;
	}

	/* use a new message structure so that we can modify it */
	msg = ldb_msg_copy_shallow(ac, req->op.mod.message);
	if (msg == NULL) {
		return ldb_oom(ldb);
	}

	/* - check for single-valued password attributes
	 *   (if not return "CONSTRAINT_VIOLATION")
	 * - check that for a password change operation one add and one delete
	 *   operation exists
	 *   (if not return "CONSTRAINT_VIOLATION" or "UNWILLING_TO_PERFORM")
	 * - check that a password change and a password set operation cannot
	 *   be mixed
	 *   (if not return "UNWILLING_TO_PERFORM")
	 * - remove all password attributes modifications from the first change
	 *   operation (anything without the passwords) - we will make the real
	 *   modification later */
	del_attr_cnt = 0;
	add_attr_cnt = 0;
	rep_attr_cnt = 0;
	for (l = passwordAttrs; *l != NULL; l++) {
		if ((!ac->userPassword) &&
		    (ldb_attr_cmp(*l, "userPassword") == 0)) {
			continue;
		}

		while ((passwordAttr = ldb_msg_find_element(msg, *l)) != NULL) {
			unsigned int mtype = LDB_FLAG_MOD_TYPE(passwordAttr->flags);
			unsigned int nvalues = passwordAttr->num_values;

			if (mtype == LDB_FLAG_MOD_DELETE) {
				++del_attr_cnt;
			}
			if (mtype == LDB_FLAG_MOD_ADD) {
				++add_attr_cnt;
			}
			if (mtype == LDB_FLAG_MOD_REPLACE) {
				++rep_attr_cnt;
			}
			if ((nvalues != 1) && (mtype == LDB_FLAG_MOD_ADD)) {
				talloc_free(ac);
				ldb_asprintf_errstring(ldb,
						       "'%s' attribute must have exactly one value on add operations!",
						       *l);
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}
			if ((nvalues > 1) && (mtype == LDB_FLAG_MOD_DELETE)) {
				talloc_free(ac);
				ldb_asprintf_errstring(ldb,
						       "'%s' attribute must have zero or one value(s) on delete operations!",
						       *l);
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}
			ldb_msg_remove_element(msg, passwordAttr);
		}
	}
	if ((del_attr_cnt == 0) && (add_attr_cnt > 0)) {
		talloc_free(ac);
		ldb_set_errstring(ldb,
				  "Only the add action for a password change specified!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	if ((del_attr_cnt > 1) || (add_attr_cnt > 1)) {
		talloc_free(ac);
		ldb_set_errstring(ldb,
				  "Only one delete and one add action for a password change allowed!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	if ((rep_attr_cnt > 0) && ((del_attr_cnt > 0) || (add_attr_cnt > 0))) {
		talloc_free(ac);
		ldb_set_errstring(ldb,
				  "Either a password change or a password set operation is allowed!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	restore = ldb_request_get_control(req,
					DSDB_CONTROL_RESTORE_TOMBSTONE_OID);
	if (restore == NULL) {
		/*
		 * A tomstone reanimation generates a double update
		 * of pwdLastSet.
		 *
		 * So we only remove it without the
		 * DSDB_CONTROL_RESTORE_TOMBSTONE_OID control.
		 */
		ldb_msg_remove_attr(msg, "pwdLastSet");
	}


	/* if there was nothing else to be modified skip to next step */
	if (msg->num_elements == 0) {
		return password_hash_mod_search_self(ac);
	}

	/*
	 * Now we apply all changes remaining in msg
	 * and remove them from our final update_msg
	 */

	for (i = 0; i < msg->num_elements; i++) {
		ldb_msg_remove_attr(ac->update_msg,
				    msg->elements[i].name);
	}

	ret = ldb_build_mod_req(&down_req, ldb, ac,
				msg,
				req->controls,
				ac, ph_modify_callback,
				req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(module, down_req);
}

static int ph_modify_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ph_context *ac;

	ac = talloc_get_type(req->context, struct ph_context);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	if (ares->type == LDB_REPLY_REFERRAL) {
		return ldb_module_send_referral(ac->req, ares->referral);
	}

	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	talloc_free(ares);

	return password_hash_mod_search_self(ac);
}

static int ph_mod_search_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct ph_context *ac;
	int ret = LDB_SUCCESS;

	ac = talloc_get_type(req->context, struct ph_context);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	/* we are interested only in the single reply (base search) */
	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		/* Make sure we are performing the password change action on a
		 * (for us) valid object. Those are instances of either "user"
		 * and/or "inetOrgPerson". Otherwise continue with the
		 * submodules. */
		if ((!ldb_msg_check_string_attribute(ares->message, "objectClass", "user"))
			&& (!ldb_msg_check_string_attribute(ares->message, "objectClass", "inetOrgPerson"))) {
			talloc_free(ares);

			if (ldb_msg_find_element(ac->req->op.mod.message, "clearTextPassword") != NULL) {
				ldb_set_errstring(ldb,
						  "'clearTextPassword' is only allowed on objects of class 'user' and/or 'inetOrgPerson'!");
				ret = LDB_ERR_NO_SUCH_ATTRIBUTE;
				goto done;
			}

			ret = ldb_next_request(ac->module, ac->req);
			goto done;
		}

		if (ac->search_res != NULL) {
			talloc_free(ares);

			ldb_set_errstring(ldb, "Too many results");
			ret = LDB_ERR_OPERATIONS_ERROR;
			goto done;
		}

		ac->search_res = talloc_steal(ac, ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore anything else for now */
		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_DONE:
		talloc_free(ares);

		/* get user domain data */
		ret = build_domain_data_request(ac);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}

		ret = ldb_next_request(ac->module, ac->dom_req);
		break;
	}

done:
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

static int password_hash_mod_search_self(struct ph_context *ac)
{
	struct ldb_context *ldb;
	static const char * const attrs[] = { "objectClass",
					      "userAccountControl",
					      "msDS-ResultantPSO",
					      "msDS-User-Account-Control-Computed",
					      "pwdLastSet",
					      "sAMAccountName",
					      "objectSid",
					      "userPrincipalName",
					      "displayName",
					      "supplementalCredentials",
					      "lmPwdHistory",
					      "ntPwdHistory",
					      "dBCSPwd",
					      "unicodePwd",
					      "badPasswordTime",
					      "badPwdCount",
					      "lockoutTime",
					      "msDS-SecondaryKrbTgtNumber",
					      NULL };
	struct ldb_request *search_req;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	ret = ldb_build_search_req(&search_req, ldb, ac,
				   ac->req->op.mod.message->dn,
				   LDB_SCOPE_BASE,
				   "(objectclass=*)",
				   attrs,
				   NULL,
				   ac, ph_mod_search_callback,
				   ac->req);
	LDB_REQ_SET_LOCATION(search_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, search_req);
}

static int password_hash_mod_do_mod(struct ph_context *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct ldb_request *mod_req;
	struct setup_password_fields_io io;
	int ret;

	/* Prepare the internal data structure containing the passwords */
	ret = setup_io(ac, ac->req->op.mod.message,
		       ac->search_res->message, &io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = setup_password_fields(&io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = check_password_restrictions_and_log(&io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = setup_smartcard_reset(&io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = update_final_msg(&io);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_build_mod_req(&mod_req, ldb, ac,
				ac->update_msg,
				ac->req->controls,
				ac, ph_op_callback,
				ac->req);
	LDB_REQ_SET_LOCATION(mod_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, mod_req);
}

static const struct ldb_module_ops ldb_password_hash_module_ops = {
	.name          = "password_hash",
	.add           = password_hash_add,
	.modify        = password_hash_modify
};

int ldb_password_hash_module_init(const char *version)
{
#ifdef ENABLE_GPGME
	const char *gversion = NULL;
#endif /* ENABLE_GPGME */

	LDB_MODULE_CHECK_VERSION(version);

#ifdef ENABLE_GPGME
	/*
	 * Note: this sets a SIGPIPE handler
	 * if none is active already. See:
	 * https://www.gnupg.org/documentation/manuals/gpgme/Signal-Handling.html#Signal-Handling
	 */
	gversion = gpgme_check_version(MINIMUM_GPGME_VERSION);
	if (gversion == NULL) {
		fprintf(stderr, "%s() in %s version[%s]: "
			"gpgme_check_version(%s) not available, "
			"gpgme_check_version(NULL) => '%s'\n",
			__func__, __FILE__, version,
			MINIMUM_GPGME_VERSION, gpgme_check_version(NULL));
		return LDB_ERR_UNAVAILABLE;
	}
#endif /* ENABLE_GPGME */

	return ldb_register_module(&ldb_password_hash_module_ops);
}
