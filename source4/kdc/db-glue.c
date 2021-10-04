/*
   Unix SMB/CIFS implementation.

   Database Glue between Samba and the KDC

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2009
   Copyright (C) Simo Sorce <idra@samba.org> 2010

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
#include "libcli/security/security.h"
#include "auth/auth.h"
#include "auth/auth_sam.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"
#include "../lib/crypto/md4.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "kdc/sdb.h"
#include "kdc/samba_kdc.h"
#include "kdc/db-glue.h"
#include "librpc/gen_ndr/ndr_irpc_c.h"
#include "lib/messaging/irpc.h"


#define SAMBA_KVNO_GET_KRBTGT(kvno) \
	((uint16_t)(((uint32_t)kvno) >> 16))

#define SAMBA_KVNO_AND_KRBTGT(kvno, krbtgt) \
	((krb5_kvno)((((uint32_t)kvno) & 0xFFFF) | \
	 ((((uint32_t)krbtgt) << 16) & 0xFFFF0000)))

enum samba_kdc_ent_type
{ SAMBA_KDC_ENT_TYPE_CLIENT, SAMBA_KDC_ENT_TYPE_SERVER,
  SAMBA_KDC_ENT_TYPE_KRBTGT, SAMBA_KDC_ENT_TYPE_TRUST, SAMBA_KDC_ENT_TYPE_ANY };

enum trust_direction {
	UNKNOWN = 0,
	INBOUND = LSA_TRUST_DIRECTION_INBOUND,
	OUTBOUND = LSA_TRUST_DIRECTION_OUTBOUND
};

static const char *trust_attrs[] = {
	"securityIdentifier",
	"flatName",
	"trustPartner",
	"trustAttributes",
	"trustDirection",
	"trustType",
	"msDS-TrustForestTrustInfo",
	"trustAuthIncoming",
	"trustAuthOutgoing",
	"whenCreated",
	"msDS-SupportedEncryptionTypes",
	NULL
};

/*
  send a message to the drepl server telling it to initiate a
  REPL_SECRET getncchanges extended op to fetch the users secrets
 */
static void auth_sam_trigger_repl_secret(TALLOC_CTX *mem_ctx,
                                  struct imessaging_context *msg_ctx,
                                  struct tevent_context *event_ctx,
                                  struct ldb_dn *user_dn)
{
        struct dcerpc_binding_handle *irpc_handle;
        struct drepl_trigger_repl_secret r;
        struct tevent_req *req;
        TALLOC_CTX *tmp_ctx;

        tmp_ctx = talloc_new(mem_ctx);
        if (tmp_ctx == NULL) {
                return;
        }

        irpc_handle = irpc_binding_handle_by_name(tmp_ctx, msg_ctx,
                                                  "dreplsrv",
                                                  &ndr_table_irpc);
        if (irpc_handle == NULL) {
                DEBUG(1,(__location__ ": Unable to get binding handle for dreplsrv\n"));
                TALLOC_FREE(tmp_ctx);
                return;
        }

        r.in.user_dn = ldb_dn_get_linearized(user_dn);

        /*
         * This seem to rely on the current IRPC implementation,
         * which delivers the message in the _send function.
         *
         * TODO: we need a ONE_WAY IRPC handle and register
         * a callback and wait for it to be triggered!
         */
        req = dcerpc_drepl_trigger_repl_secret_r_send(tmp_ctx,
                                                      event_ctx,
                                                      irpc_handle,
                                                      &r);

        /* we aren't interested in a reply */
        talloc_free(req);
        TALLOC_FREE(tmp_ctx);
}

static time_t ldb_msg_find_krb5time_ldap_time(struct ldb_message *msg, const char *attr, time_t default_val)
{
    const char *tmp;
    const char *gentime;
    struct tm tm;

    gentime = ldb_msg_find_attr_as_string(msg, attr, NULL);
    if (!gentime)
	return default_val;

    tmp = strptime(gentime, "%Y%m%d%H%M%SZ", &tm);
    if (tmp == NULL) {
	    return default_val;
    }

    return timegm(&tm);
}

static struct SDBFlags uf2SDBFlags(krb5_context context, uint32_t userAccountControl, enum samba_kdc_ent_type ent_type)
{
	struct SDBFlags flags = int2SDBFlags(0);

	/* we don't allow kadmin deletes */
	flags.immutable = 1;

	/* mark the principal as invalid to start with */
	flags.invalid = 1;

	flags.renewable = 1;

	/* All accounts are servers, but this may be disabled again in the caller */
	flags.server = 1;

	/* Account types - clear the invalid bit if it turns out to be valid */
	if (userAccountControl & UF_NORMAL_ACCOUNT) {
		if (ent_type == SAMBA_KDC_ENT_TYPE_CLIENT || ent_type == SAMBA_KDC_ENT_TYPE_ANY) {
			flags.client = 1;
		}
		flags.invalid = 0;
	}

	if (userAccountControl & UF_INTERDOMAIN_TRUST_ACCOUNT) {
		if (ent_type == SAMBA_KDC_ENT_TYPE_CLIENT || ent_type == SAMBA_KDC_ENT_TYPE_ANY) {
			flags.client = 1;
		}
		flags.invalid = 0;
	}
	if (userAccountControl & UF_WORKSTATION_TRUST_ACCOUNT) {
		if (ent_type == SAMBA_KDC_ENT_TYPE_CLIENT || ent_type == SAMBA_KDC_ENT_TYPE_ANY) {
			flags.client = 1;
		}
		flags.invalid = 0;
	}
	if (userAccountControl & UF_SERVER_TRUST_ACCOUNT) {
		if (ent_type == SAMBA_KDC_ENT_TYPE_CLIENT || ent_type == SAMBA_KDC_ENT_TYPE_ANY) {
			flags.client = 1;
		}
		flags.invalid = 0;
	}

	/* Not permitted to act as a client if disabled */
	if (userAccountControl & UF_ACCOUNTDISABLE) {
		flags.client = 0;
	}
	if (userAccountControl & UF_LOCKOUT) {
		flags.locked_out = 1;
	}
/*
	if (userAccountControl & UF_PASSWORD_NOTREQD) {
		flags.invalid = 1;
	}
*/
/*
	UF_PASSWORD_CANT_CHANGE and UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED are irrelevent
*/
	if (userAccountControl & UF_TEMP_DUPLICATE_ACCOUNT) {
		flags.invalid = 1;
	}

/* UF_DONT_EXPIRE_PASSWD and UF_USE_DES_KEY_ONLY handled in samba_kdc_message2entry() */

/*
	if (userAccountControl & UF_MNS_LOGON_ACCOUNT) {
		flags.invalid = 1;
	}
*/
	if (userAccountControl & UF_SMARTCARD_REQUIRED) {
		flags.require_hwauth = 1;
	}
	if (userAccountControl & UF_TRUSTED_FOR_DELEGATION) {
		flags.ok_as_delegate = 1;
	}
	if (userAccountControl & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) {
		/*
		 * this is confusing...
		 *
		 * UF_TRUSTED_FOR_DELEGATION
		 * => ok_as_delegate
		 *
		 * and
		 *
		 * UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
		 * => trusted_for_delegation
		 */
		flags.trusted_for_delegation = 1;
	}
	if (!(userAccountControl & UF_NOT_DELEGATED)) {
		flags.forwardable = 1;
		flags.proxiable = 1;
	}

	if (userAccountControl & UF_DONT_REQUIRE_PREAUTH) {
		flags.require_preauth = 0;
	} else {
		flags.require_preauth = 1;

	}
	return flags;
}

static int samba_kdc_entry_destructor(struct samba_kdc_entry *p)
{
	if (p->entry_ex != NULL) {
		struct sdb_entry_ex *entry_ex = p->entry_ex;
		free_sdb_entry(&entry_ex->entry);
	}

	return 0;
}

/*
 * Sort keys in descending order of strength.
 *
 * Explanaton from Greg Hudson:
 *
 * To encrypt tickets only the first returned key is used by the MIT KDC.  The
 * other keys just communicate support for session key enctypes, and aren't
 * really used.  The encryption key for the ticket enc part doesn't have
 * to be of a type requested by the client. The session key enctype is chosen
 * based on the client preference order, limited by the set of enctypes present
 * in the server keys (unless the string attribute is set on the server
 * principal overriding that set).
 */
static int samba_kdc_sort_encryption_keys(struct sdb_entry_ex *entry_ex)
{
	unsigned int i, j, idx = 0;
	static const krb5_enctype etype_list[] = {
		ENCTYPE_AES256_CTS_HMAC_SHA1_96,
		ENCTYPE_AES128_CTS_HMAC_SHA1_96,
		ENCTYPE_DES3_CBC_SHA1,
		ENCTYPE_ARCFOUR_HMAC,
		ENCTYPE_DES_CBC_MD5,
		ENCTYPE_DES_CBC_MD4,
		ENCTYPE_DES_CBC_CRC,
		ENCTYPE_NULL
	};
	size_t etype_len = ARRAY_SIZE(etype_list);
	size_t keys_size = entry_ex->entry.keys.len;
	struct sdb_key *keys = entry_ex->entry.keys.val;
	struct sdb_key *sorted_keys;

	sorted_keys = calloc(keys_size, sizeof(struct sdb_key));
	if (sorted_keys == NULL) {
		return -1;
	}

	for (i = 0; i < etype_len; i++) {
		for (j = 0; j < keys_size; j++) {
			const struct sdb_key skey = keys[j];

			if (idx == keys_size) {
				break;
			}

			if (KRB5_KEY_TYPE(&skey.key) == etype_list[i]) {
				sorted_keys[idx] = skey;
				idx++;
			}
		}
	}

	/* Paranoia: Something went wrong during data copy */
	if (idx != keys_size) {
		free(sorted_keys);
		return -1;
	}

	free(entry_ex->entry.keys.val);
	entry_ex->entry.keys.val = sorted_keys;

	return 0;
}

static krb5_error_code samba_kdc_message2entry_keys(krb5_context context,
						    struct samba_kdc_db_context *kdc_db_ctx,
						    TALLOC_CTX *mem_ctx,
						    struct ldb_message *msg,
						    uint32_t rid,
						    bool is_rodc,
						    uint32_t userAccountControl,
						    enum samba_kdc_ent_type ent_type,
						    struct sdb_entry_ex *entry_ex)
{
	krb5_error_code ret = 0;
	enum ndr_err_code ndr_err;
	struct samr_Password *hash;
	const struct ldb_val *sc_val;
	struct supplementalCredentialsBlob scb;
	struct supplementalCredentialsPackage *scpk = NULL;
	bool newer_keys = false;
	struct package_PrimaryKerberosBlob _pkb;
	struct package_PrimaryKerberosCtr3 *pkb3 = NULL;
	struct package_PrimaryKerberosCtr4 *pkb4 = NULL;
	uint16_t i;
	uint16_t allocated_keys = 0;
	int rodc_krbtgt_number = 0;
	int kvno = 0;
	uint32_t supported_enctypes
		= ldb_msg_find_attr_as_uint(msg,
					    "msDS-SupportedEncryptionTypes",
					    0);

	if (rid == DOMAIN_RID_KRBTGT || is_rodc) {
		/* KDCs (and KDCs on RODCs) use AES */
		supported_enctypes |= ENC_HMAC_SHA1_96_AES128 | ENC_HMAC_SHA1_96_AES256;
	} else if (userAccountControl & (UF_PARTIAL_SECRETS_ACCOUNT|UF_SERVER_TRUST_ACCOUNT)) {
		/* DCs and RODCs comptuer accounts use AES */
		supported_enctypes |= ENC_HMAC_SHA1_96_AES128 | ENC_HMAC_SHA1_96_AES256;
	} else if (ent_type == SAMBA_KDC_ENT_TYPE_CLIENT ||
		   (ent_type == SAMBA_KDC_ENT_TYPE_ANY)) {
		/* for AS-REQ the client chooses the enc types it
		 * supports, and this will vary between computers a
		 * user logs in from.
		 *
		 * likewise for 'any' return as much as is supported,
		 * to export into a keytab */
		supported_enctypes = ENC_ALL_TYPES;
	}

	/* If UF_USE_DES_KEY_ONLY has been set, then don't allow use of the newer enc types */
	if (userAccountControl & UF_USE_DES_KEY_ONLY) {
		supported_enctypes = 0;
	} else {
		/* Otherwise, add in the default enc types */
		supported_enctypes |= ENC_RC4_HMAC_MD5;
	}

	/* Is this the krbtgt or a RODC krbtgt */
	if (is_rodc) {
		rodc_krbtgt_number = ldb_msg_find_attr_as_int(msg, "msDS-SecondaryKrbTgtNumber", -1);

		if (rodc_krbtgt_number == -1) {
			return EINVAL;
		}
	}

	entry_ex->entry.keys.val = NULL;
	entry_ex->entry.keys.len = 0;
	entry_ex->entry.kvno = 0;

	if ((ent_type == SAMBA_KDC_ENT_TYPE_CLIENT)
	    && (userAccountControl & UF_SMARTCARD_REQUIRED)) {
		uint8_t secretbuffer[32];

		/*
		 * Fake keys until we have a better way to reject
		 * non-pkinit requests.
		 *
		 * We just need to indicate which encryption types are
		 * supported.
		 */
		generate_secret_buffer(secretbuffer, sizeof(secretbuffer));

		allocated_keys = 3;
		entry_ex->entry.keys.len = 0;
		entry_ex->entry.keys.val = calloc(allocated_keys, sizeof(struct sdb_key));
		if (entry_ex->entry.keys.val == NULL) {
			ZERO_STRUCT(secretbuffer);
			ret = ENOMEM;
			goto out;
		}

		if (supported_enctypes & ENC_HMAC_SHA1_96_AES256) {
			struct sdb_key key = {};

			ret = smb_krb5_keyblock_init_contents(context,
							      ENCTYPE_AES256_CTS_HMAC_SHA1_96,
							      secretbuffer, 32,
							      &key.key);
			if (ret) {
				ZERO_STRUCT(secretbuffer);
				goto out;
			}

			entry_ex->entry.keys.val[entry_ex->entry.keys.len] = key;
			entry_ex->entry.keys.len++;
		}

		if (supported_enctypes & ENC_HMAC_SHA1_96_AES128) {
			struct sdb_key key = {};

			ret = smb_krb5_keyblock_init_contents(context,
							      ENCTYPE_AES128_CTS_HMAC_SHA1_96,
							      secretbuffer, 16,
							      &key.key);
			if (ret) {
				ZERO_STRUCT(secretbuffer);
				goto out;
			}

			entry_ex->entry.keys.val[entry_ex->entry.keys.len] = key;
			entry_ex->entry.keys.len++;
		}

		if (supported_enctypes & ENC_RC4_HMAC_MD5) {
			struct sdb_key key = {};

			ret = smb_krb5_keyblock_init_contents(context,
							      ENCTYPE_ARCFOUR_HMAC,
							      secretbuffer, 16,
							      &key.key);
			if (ret) {
				ZERO_STRUCT(secretbuffer);
				goto out;
			}

			entry_ex->entry.keys.val[entry_ex->entry.keys.len] = key;
			entry_ex->entry.keys.len++;
		}

		ret = 0;
		goto out;
	}

	kvno = ldb_msg_find_attr_as_int(msg, "msDS-KeyVersionNumber", 0);
	if (is_rodc) {
		kvno = SAMBA_KVNO_AND_KRBTGT(kvno, rodc_krbtgt_number);
	}
	entry_ex->entry.kvno = kvno;

	/* Get keys from the db */

	hash = samdb_result_hash(mem_ctx, msg, "unicodePwd");
	sc_val = ldb_msg_find_ldb_val(msg, "supplementalCredentials");

	/* unicodePwd for enctype 0x17 (23) if present */
	if (hash) {
		allocated_keys++;
	}

	/* supplementalCredentials if present */
	if (sc_val) {
		ndr_err = ndr_pull_struct_blob_all(sc_val, mem_ctx, &scb,
						   (ndr_pull_flags_fn_t)ndr_pull_supplementalCredentialsBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			dump_data(0, sc_val->data, sc_val->length);
			ret = EINVAL;
			goto out;
		}

		if (scb.sub.signature != SUPPLEMENTAL_CREDENTIALS_SIGNATURE) {
			if (scb.sub.num_packages != 0) {
				NDR_PRINT_DEBUG(supplementalCredentialsBlob, &scb);
				ret = EINVAL;
				goto out;
			}
		}

		for (i=0; i < scb.sub.num_packages; i++) {
			if (strcmp("Primary:Kerberos-Newer-Keys", scb.sub.packages[i].name) == 0) {
				scpk = &scb.sub.packages[i];
				if (!scpk->data || !scpk->data[0]) {
					scpk = NULL;
					continue;
				}
				newer_keys = true;
				break;
			} else if (strcmp("Primary:Kerberos", scb.sub.packages[i].name) == 0) {
				scpk = &scb.sub.packages[i];
				if (!scpk->data || !scpk->data[0]) {
					scpk = NULL;
				}
				/*
				 * we don't break here in hope to find
				 * a Kerberos-Newer-Keys package
				 */
			}
		}
	}
	/*
	 * Primary:Kerberos-Newer-Keys or Primary:Kerberos element
	 * of supplementalCredentials
	 */
	if (scpk) {
		DATA_BLOB blob;

		blob = strhex_to_data_blob(mem_ctx, scpk->data);
		if (!blob.data) {
			ret = ENOMEM;
			goto out;
		}

		/* we cannot use ndr_pull_struct_blob_all() here, as w2k and w2k3 add padding bytes */
		ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &_pkb,
					       (ndr_pull_flags_fn_t)ndr_pull_package_PrimaryKerberosBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			ret = EINVAL;
			krb5_set_error_message(context, ret, "samba_kdc_message2entry_keys: could not parse package_PrimaryKerberosBlob");
			krb5_warnx(context, "samba_kdc_message2entry_keys: could not parse package_PrimaryKerberosBlob");
			goto out;
		}

		if (newer_keys && _pkb.version != 4) {
			ret = EINVAL;
			krb5_set_error_message(context, ret, "samba_kdc_message2entry_keys: Primary:Kerberos-Newer-Keys not version 4");
			krb5_warnx(context, "samba_kdc_message2entry_keys: Primary:Kerberos-Newer-Keys not version 4");
			goto out;
		}

		if (!newer_keys && _pkb.version != 3) {
			ret = EINVAL;
			krb5_set_error_message(context, ret, "samba_kdc_message2entry_keys: could not parse Primary:Kerberos not version 3");
			krb5_warnx(context, "samba_kdc_message2entry_keys: could not parse Primary:Kerberos not version 3");
			goto out;
		}

		if (_pkb.version == 4) {
			pkb4 = &_pkb.ctr.ctr4;
			allocated_keys += pkb4->num_keys;
		} else if (_pkb.version == 3) {
			pkb3 = &_pkb.ctr.ctr3;
			allocated_keys += pkb3->num_keys;
		}
	}

	if (allocated_keys == 0) {
		if (kdc_db_ctx->rodc) {
			/* We are on an RODC, but don't have keys for this account.  Signal this to the caller */
			auth_sam_trigger_repl_secret(kdc_db_ctx, kdc_db_ctx->msg_ctx,
						     kdc_db_ctx->ev_ctx, msg->dn);
			return SDB_ERR_NOT_FOUND_HERE;
		}

		/* oh, no password.  Apparently (comment in
		 * hdb-ldap.c) this violates the ASN.1, but this
		 * allows an entry with no keys (yet). */
		return 0;
	}

	/* allocate space to decode into */
	entry_ex->entry.keys.len = 0;
	entry_ex->entry.keys.val = calloc(allocated_keys, sizeof(struct sdb_key));
	if (entry_ex->entry.keys.val == NULL) {
		ret = ENOMEM;
		goto out;
	}

	if (hash && (supported_enctypes & ENC_RC4_HMAC_MD5)) {
		struct sdb_key key = {};

		ret = smb_krb5_keyblock_init_contents(context,
						      ENCTYPE_ARCFOUR_HMAC,
						      hash->hash,
						      sizeof(hash->hash),
						      &key.key);
		if (ret) {
			goto out;
		}

		entry_ex->entry.keys.val[entry_ex->entry.keys.len] = key;
		entry_ex->entry.keys.len++;
	}

	if (pkb4) {
		for (i=0; i < pkb4->num_keys; i++) {
			struct sdb_key key = {};

			if (!pkb4->keys[i].value) continue;

			if (!(kerberos_enctype_to_bitmap(pkb4->keys[i].keytype) & supported_enctypes)) {
				continue;
			}

			if (pkb4->salt.string) {
				DATA_BLOB salt;

				salt = data_blob_string_const(pkb4->salt.string);

				key.salt = calloc(1, sizeof(*key.salt));
				if (key.salt == NULL) {
					ret = ENOMEM;
					goto out;
				}

				key.salt->type = KRB5_PW_SALT;

				ret = smb_krb5_copy_data_contents(&key.salt->salt,
								  salt.data,
								  salt.length);
				if (ret) {
					free(key.salt);
					key.salt = NULL;
					goto out;
				}
			}

			/* TODO: maybe pass the iteration_count somehow... */

			ret = smb_krb5_keyblock_init_contents(context,
							      pkb4->keys[i].keytype,
							      pkb4->keys[i].value->data,
							      pkb4->keys[i].value->length,
							      &key.key);
			if (ret) {
				if (key.salt) {
					smb_krb5_free_data_contents(context, &key.salt->salt);
					free(key.salt);
					key.salt = NULL;
				}
				if (ret == KRB5_PROG_ETYPE_NOSUPP) {
					DEBUG(2,("Unsupported keytype ignored - type %u\n",
						 pkb4->keys[i].keytype));
					ret = 0;
					continue;
				}
				goto out;
			}

			entry_ex->entry.keys.val[entry_ex->entry.keys.len] = key;
			entry_ex->entry.keys.len++;
		}
	} else if (pkb3) {
		for (i=0; i < pkb3->num_keys; i++) {
			struct sdb_key key = {};

			if (!pkb3->keys[i].value) continue;

			if (!(kerberos_enctype_to_bitmap(pkb3->keys[i].keytype) & supported_enctypes)) {
				continue;
			}

			if (pkb3->salt.string) {
				DATA_BLOB salt;

				salt = data_blob_string_const(pkb3->salt.string);

				key.salt = calloc(1, sizeof(*key.salt));
				if (key.salt == NULL) {
					ret = ENOMEM;
					goto out;
				}

				key.salt->type = KRB5_PW_SALT;

				ret = smb_krb5_copy_data_contents(&key.salt->salt,
								  salt.data,
								  salt.length);
				if (ret) {
					free(key.salt);
					key.salt = NULL;
					goto out;
				}
			}

			ret = smb_krb5_keyblock_init_contents(context,
							      pkb3->keys[i].keytype,
							      pkb3->keys[i].value->data,
							      pkb3->keys[i].value->length,
							      &key.key);
			if (ret) {
				if (key.salt) {
					smb_krb5_free_data_contents(context, &key.salt->salt);
					free(key.salt);
					key.salt = NULL;
				}
				if (ret == KRB5_PROG_ETYPE_NOSUPP) {
					DEBUG(2,("Unsupported keytype ignored - type %u\n",
						 pkb3->keys[i].keytype));
					ret = 0;
					continue;
				}
				goto out;
			}

			entry_ex->entry.keys.val[entry_ex->entry.keys.len] = key;
			entry_ex->entry.keys.len++;
		}
	}

out:
	if (ret != 0) {
		entry_ex->entry.keys.len = 0;
	} else if (entry_ex->entry.keys.len > 0 &&
		   entry_ex->entry.keys.val != NULL) {
		ret = samba_kdc_sort_encryption_keys(entry_ex);
		if (ret != 0) {
			entry_ex->entry.keys.len = 0;
			ret = ENOMEM;
		}
	}
	if (entry_ex->entry.keys.len == 0 && entry_ex->entry.keys.val) {
		free(entry_ex->entry.keys.val);
		entry_ex->entry.keys.val = NULL;
	}
	return ret;
}

static int principal_comp_strcmp_int(krb5_context context,
				     krb5_const_principal principal,
				     unsigned int component,
				     const char *string,
				     bool do_strcasecmp)
{
	const char *p;
	size_t len;

#if defined(HAVE_KRB5_PRINCIPAL_GET_COMP_STRING)
	p = krb5_principal_get_comp_string(context, principal, component);
	if (p == NULL) {
		return -1;
	}
	len = strlen(p);
#else
	krb5_data *d;
	if (component >= krb5_princ_size(context, principal)) {
		return -1;
	}

	d = krb5_princ_component(context, principal, component);
	if (d == NULL) {
		return -1;
	}

	p = d->data;
	len = d->length;
#endif
	if (do_strcasecmp) {
		return strncasecmp(p, string, len);
	} else {
		return strncmp(p, string, len);
	}
}

static int principal_comp_strcasecmp(krb5_context context,
				     krb5_const_principal principal,
				     unsigned int component,
				     const char *string)
{
	return principal_comp_strcmp_int(context, principal,
					 component, string, true);
}

static int principal_comp_strcmp(krb5_context context,
				 krb5_const_principal principal,
				 unsigned int component,
				 const char *string)
{
	return principal_comp_strcmp_int(context, principal,
					 component, string, false);
}

/*
 * Construct an hdb_entry from a directory entry.
 */
static krb5_error_code samba_kdc_message2entry(krb5_context context,
					       struct samba_kdc_db_context *kdc_db_ctx,
					       TALLOC_CTX *mem_ctx,
					       krb5_const_principal principal,
					       enum samba_kdc_ent_type ent_type,
					       unsigned flags,
					       struct ldb_dn *realm_dn,
					       struct ldb_message *msg,
					       struct sdb_entry_ex *entry_ex)
{
	struct loadparm_context *lp_ctx = kdc_db_ctx->lp_ctx;
	uint32_t userAccountControl;
	uint32_t msDS_User_Account_Control_Computed;
	krb5_error_code ret = 0;
	krb5_boolean is_computer = FALSE;

	struct samba_kdc_entry *p;
	NTTIME acct_expiry;
	NTSTATUS status;

	uint32_t rid;
	bool is_rodc = false;
	struct ldb_message_element *objectclasses;
	struct ldb_val computer_val;
	const char *samAccountName = ldb_msg_find_attr_as_string(msg, "samAccountName", NULL);
	computer_val.data = discard_const_p(uint8_t,"computer");
	computer_val.length = strlen((const char *)computer_val.data);

	if (ldb_msg_find_element(msg, "msDS-SecondaryKrbTgtNumber")) {
		is_rodc = true;
	}

	if (!samAccountName) {
		ret = ENOENT;
		krb5_set_error_message(context, ret, "samba_kdc_message2entry: no samAccountName present");
		goto out;
	}

	objectclasses = ldb_msg_find_element(msg, "objectClass");

	if (objectclasses && ldb_msg_find_val(objectclasses, &computer_val)) {
		is_computer = TRUE;
	}

	ZERO_STRUCTP(entry_ex);

	p = talloc_zero(mem_ctx, struct samba_kdc_entry);
	if (!p) {
		ret = ENOMEM;
		goto out;
	}

	p->is_rodc = is_rodc;
	p->kdc_db_ctx = kdc_db_ctx;
	p->realm_dn = talloc_reference(p, realm_dn);
	if (!p->realm_dn) {
		ret = ENOMEM;
		goto out;
	}

	talloc_set_destructor(p, samba_kdc_entry_destructor);

	entry_ex->ctx = p;

	userAccountControl = ldb_msg_find_attr_as_uint(msg, "userAccountControl", 0);

	msDS_User_Account_Control_Computed
		= ldb_msg_find_attr_as_uint(msg,
					    "msDS-User-Account-Control-Computed",
					    UF_ACCOUNTDISABLE);

	/*
	 * This brings in the lockout flag, block the account if not
	 * found.  We need the weird UF_ACCOUNTDISABLE check because
	 * we do not want to fail open if the value is not returned,
	 * but 0 is a valid value (all OK)
	 */
	if (msDS_User_Account_Control_Computed == UF_ACCOUNTDISABLE) {
		ret = EINVAL;
		krb5_set_error_message(context, ret, "samba_kdc_message2entry: "
				"no msDS-User-Account-Control-Computed present");
		goto out;
	} else {
		userAccountControl |= msDS_User_Account_Control_Computed;
	}

	/* 
	 * If we are set to canonicalize, we get back the fixed UPPER
	 * case realm, and the real username (ie matching LDAP
	 * samAccountName) 
	 *
	 * Otherwise, if we are set to enterprise, we
	 * get back the whole principal as-sent 
	 *
	 * Finally, if we are not set to canonicalize, we get back the
	 * fixed UPPER case realm, but the as-sent username
	 */

	if (ent_type == SAMBA_KDC_ENT_TYPE_KRBTGT) {
		p->is_krbtgt = true;

		if (flags & (SDB_F_CANON)) {
			/*
			 * When requested to do so, ensure that the
			 * both realm values in the principal are set
			 * to the upper case, canonical realm
			 */
			ret = smb_krb5_make_principal(context, &entry_ex->entry.principal,
						      lpcfg_realm(lp_ctx), "krbtgt",
						      lpcfg_realm(lp_ctx), NULL);
			if (ret) {
				krb5_clear_error_message(context);
				goto out;
			}
			smb_krb5_principal_set_type(context, entry_ex->entry.principal, KRB5_NT_SRV_INST);
		} else {
			ret = krb5_copy_principal(context, principal, &entry_ex->entry.principal);
			if (ret) {
				krb5_clear_error_message(context);
				goto out;
			}
			/*
			 * this appears to be required regardless of
			 * the canonicalize flag from the client
			 */
			ret = smb_krb5_principal_set_realm(context, entry_ex->entry.principal, lpcfg_realm(lp_ctx));
			if (ret) {
				krb5_clear_error_message(context);
				goto out;
			}
		}

	} else if (ent_type == SAMBA_KDC_ENT_TYPE_ANY && principal == NULL) {
		ret = smb_krb5_make_principal(context, &entry_ex->entry.principal, lpcfg_realm(lp_ctx), samAccountName, NULL);
		if (ret) {
			krb5_clear_error_message(context);
			goto out;
		}
	} else if ((flags & SDB_F_CANON) && (flags & SDB_F_FOR_AS_REQ)) {
		/*
		 * SDB_F_CANON maps from the canonicalize flag in the
		 * packet, and has a different meaning between AS-REQ
		 * and TGS-REQ.  We only change the principal in the AS-REQ case
		 */
		ret = smb_krb5_make_principal(context, &entry_ex->entry.principal, lpcfg_realm(lp_ctx), samAccountName, NULL);
		if (ret) {
			krb5_clear_error_message(context);
			goto out;
		}
	} else {
		ret = krb5_copy_principal(context, principal, &entry_ex->entry.principal);
		if (ret) {
			krb5_clear_error_message(context);
			goto out;
		}

		if (smb_krb5_principal_get_type(context, principal) != KRB5_NT_ENTERPRISE_PRINCIPAL) {
			/* While we have copied the client principal, tests
			 * show that Win2k3 returns the 'corrected' realm, not
			 * the client-specified realm.  This code attempts to
			 * replace the client principal's realm with the one
			 * we determine from our records */
			
			/* this has to be with malloc() */
			ret = smb_krb5_principal_set_realm(context, entry_ex->entry.principal, lpcfg_realm(lp_ctx));
			if (ret) {
				krb5_clear_error_message(context);
				goto out;
			}
		}
	}

	/* First try and figure out the flags based on the userAccountControl */
	entry_ex->entry.flags = uf2SDBFlags(context, userAccountControl, ent_type);

	/* Windows 2008 seems to enforce this (very sensible) rule by
	 * default - don't allow offline attacks on a user's password
	 * by asking for a ticket to them as a service (encrypted with
	 * their probably patheticly insecure password) */

	if (entry_ex->entry.flags.server
	    && lpcfg_parm_bool(lp_ctx, NULL, "kdc", "require spn for service", true)) {
		if (!is_computer && !ldb_msg_find_attr_as_string(msg, "servicePrincipalName", NULL)) {
			entry_ex->entry.flags.server = 0;
		}
	}

	/*
	 * We restrict a 3-part SPN ending in my domain/realm to full
	 * domain controllers.
	 *
	 * This avoids any cases where (eg) a demoted DC still has
	 * these more restricted SPNs.
	 */
	if (krb5_princ_size(context, principal) > 2) {
		char *third_part
			= smb_krb5_principal_get_comp_string(mem_ctx,
							     context,
							     principal,
							     2);
		bool is_our_realm =
			 lpcfg_is_my_domain_or_realm(lp_ctx,
						     third_part);
		bool is_dc = userAccountControl &
			(UF_SERVER_TRUST_ACCOUNT | UF_PARTIAL_SECRETS_ACCOUNT);
		if (is_our_realm && !is_dc) {
			entry_ex->entry.flags.server = 0;
		}
	}
	/*
	 * To give the correct type of error to the client, we must
	 * not just return the entry without .server set, we must
	 * pretend the principal does not exist.  Otherwise we may
	 * return ERR_POLICY instead of
	 * KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN
	 */
	if (ent_type == SAMBA_KDC_ENT_TYPE_SERVER && entry_ex->entry.flags.server == 0) {
		ret = SDB_ERR_NOENTRY;
		krb5_set_error_message(context, ret, "samba_kdc_message2entry: no servicePrincipalName present for this server, refusing with no-such-entry");
		goto out;
	}
	if (flags & SDB_F_ADMIN_DATA) {
		/* These (created_by, modified_by) parts of the entry are not relevant for Samba4's use
		 * of the Heimdal KDC.  They are stored in a the traditional
		 * DB for audit purposes, and still form part of the structure
		 * we must return */

		/* use 'whenCreated' */
		entry_ex->entry.created_by.time = ldb_msg_find_krb5time_ldap_time(msg, "whenCreated", 0);
		/* use 'kadmin' for now (needed by mit_samba) */

		ret = smb_krb5_make_principal(context,
					      &entry_ex->entry.created_by.principal,
					      lpcfg_realm(lp_ctx), "kadmin", NULL);
		if (ret) {
			krb5_clear_error_message(context);
			goto out;
		}

		entry_ex->entry.modified_by = (struct sdb_event *) malloc(sizeof(struct sdb_event));
		if (entry_ex->entry.modified_by == NULL) {
			ret = ENOMEM;
			krb5_set_error_message(context, ret, "malloc: out of memory");
			goto out;
		}

		/* use 'whenChanged' */
		entry_ex->entry.modified_by->time = ldb_msg_find_krb5time_ldap_time(msg, "whenChanged", 0);
		/* use 'kadmin' for now (needed by mit_samba) */
		ret = smb_krb5_make_principal(context,
					      &entry_ex->entry.modified_by->principal,
					      lpcfg_realm(lp_ctx), "kadmin", NULL);
		if (ret) {
			krb5_clear_error_message(context);
			goto out;
		}
	}


	/* The lack of password controls etc applies to krbtgt by
	 * virtue of being that particular RID */
	status = dom_sid_split_rid(NULL, samdb_result_dom_sid(mem_ctx, msg, "objectSid"), NULL, &rid);

	if (!NT_STATUS_IS_OK(status)) {
		ret = EINVAL;
		goto out;
	}

	if (rid == DOMAIN_RID_KRBTGT) {
		char *realm = NULL;

		entry_ex->entry.valid_end = NULL;
		entry_ex->entry.pw_end = NULL;

		entry_ex->entry.flags.invalid = 0;
		entry_ex->entry.flags.server = 1;

		realm = smb_krb5_principal_get_realm(
			mem_ctx, context, principal);
		if (realm == NULL) {
			ret = ENOMEM;
			goto out;
		}

		/* Don't mark all requests for the krbtgt/realm as
		 * 'change password', as otherwise we could get into
		 * trouble, and not enforce the password expirty.
		 * Instead, only do it when request is for the kpasswd service */
		if (ent_type == SAMBA_KDC_ENT_TYPE_SERVER
		    && krb5_princ_size(context, principal) == 2
		    && (principal_comp_strcmp(context, principal, 0, "kadmin") == 0)
		    && (principal_comp_strcmp(context, principal, 1, "changepw") == 0)
		    && lpcfg_is_my_domain_or_realm(lp_ctx, realm)) {
			entry_ex->entry.flags.change_pw = 1;
		}

		TALLOC_FREE(realm);

		entry_ex->entry.flags.client = 0;
		entry_ex->entry.flags.forwardable = 1;
		entry_ex->entry.flags.ok_as_delegate = 1;
	} else if (is_rodc) {
		/* The RODC krbtgt account is like the main krbtgt,
		 * but it does not have a changepw or kadmin
		 * service */

		entry_ex->entry.valid_end = NULL;
		entry_ex->entry.pw_end = NULL;

		/* Also don't allow the RODC krbtgt to be a client (it should not be needed) */
		entry_ex->entry.flags.client = 0;
		entry_ex->entry.flags.invalid = 0;
		entry_ex->entry.flags.server = 1;

		entry_ex->entry.flags.client = 0;
		entry_ex->entry.flags.forwardable = 1;
		entry_ex->entry.flags.ok_as_delegate = 0;
	} else if (entry_ex->entry.flags.server && ent_type == SAMBA_KDC_ENT_TYPE_SERVER) {
		/* The account/password expiry only applies when the account is used as a
		 * client (ie password login), not when used as a server */

		/* Make very well sure we don't use this for a client,
		 * it could bypass the password restrictions */
		entry_ex->entry.flags.client = 0;

		entry_ex->entry.valid_end = NULL;
		entry_ex->entry.pw_end = NULL;

	} else {
		NTTIME must_change_time
			= samdb_result_nttime(msg,
					"msDS-UserPasswordExpiryTimeComputed",
					0);
		if (must_change_time == 0x7FFFFFFFFFFFFFFFULL) {
			entry_ex->entry.pw_end = NULL;
		} else {
			entry_ex->entry.pw_end = malloc(sizeof(*entry_ex->entry.pw_end));
			if (entry_ex->entry.pw_end == NULL) {
				ret = ENOMEM;
				goto out;
			}
			*entry_ex->entry.pw_end = nt_time_to_unix(must_change_time);
		}

		acct_expiry = samdb_result_account_expires(msg);
		if (acct_expiry == 0x7FFFFFFFFFFFFFFFULL) {
			entry_ex->entry.valid_end = NULL;
		} else {
			entry_ex->entry.valid_end = malloc(sizeof(*entry_ex->entry.valid_end));
			if (entry_ex->entry.valid_end == NULL) {
				ret = ENOMEM;
				goto out;
			}
			*entry_ex->entry.valid_end = nt_time_to_unix(acct_expiry);
		}
	}

	entry_ex->entry.valid_start = NULL;

	entry_ex->entry.max_life = malloc(sizeof(*entry_ex->entry.max_life));
	if (entry_ex->entry.max_life == NULL) {
		ret = ENOMEM;
		goto out;
	}

	if (ent_type == SAMBA_KDC_ENT_TYPE_SERVER) {
		*entry_ex->entry.max_life = kdc_db_ctx->policy.svc_tkt_lifetime;
	} else if (ent_type == SAMBA_KDC_ENT_TYPE_KRBTGT || ent_type == SAMBA_KDC_ENT_TYPE_CLIENT) {
		*entry_ex->entry.max_life = kdc_db_ctx->policy.usr_tkt_lifetime;
	} else {
		*entry_ex->entry.max_life = MIN(kdc_db_ctx->policy.svc_tkt_lifetime,
					        kdc_db_ctx->policy.usr_tkt_lifetime);
	}

	entry_ex->entry.max_renew = malloc(sizeof(*entry_ex->entry.max_life));
	if (entry_ex->entry.max_renew == NULL) {
		ret = ENOMEM;
		goto out;
	}

	*entry_ex->entry.max_renew = kdc_db_ctx->policy.renewal_lifetime;

	/* Get keys from the db */
	ret = samba_kdc_message2entry_keys(context, kdc_db_ctx, p, msg,
					   rid, is_rodc, userAccountControl,
					   ent_type, entry_ex);
	if (ret) {
		/* Could be bogus data in the entry, or out of memory */
		goto out;
	}

	p->msg = talloc_steal(p, msg);

out:
	if (ret != 0) {
		/* This doesn't free ent itself, that is for the eventual caller to do */
		sdb_free_entry(entry_ex);
		ZERO_STRUCTP(entry_ex);
	} else {
		talloc_steal(kdc_db_ctx, entry_ex->ctx);
	}

	return ret;
}

/*
 * Construct an hdb_entry from a directory entry.
 * The kvno is what the remote client asked for
 */
static krb5_error_code samba_kdc_trust_message2entry(krb5_context context,
					       struct samba_kdc_db_context *kdc_db_ctx,
					       TALLOC_CTX *mem_ctx, krb5_const_principal principal,
					       enum trust_direction direction,
					       struct ldb_dn *realm_dn,
					       unsigned flags,
					       uint32_t kvno,
					       struct ldb_message *msg,
					       struct sdb_entry_ex *entry_ex)
{
	struct loadparm_context *lp_ctx = kdc_db_ctx->lp_ctx;
	const char *our_realm = lpcfg_realm(lp_ctx);
	char *partner_realm = NULL;
	const char *realm = NULL;
	const char *krbtgt_realm = NULL;
	DATA_BLOB password_utf16 = data_blob_null;
	DATA_BLOB password_utf8 = data_blob_null;
	struct samr_Password _password_hash;
	const struct samr_Password *password_hash = NULL;
	const struct ldb_val *password_val;
	struct trustAuthInOutBlob password_blob;
	struct samba_kdc_entry *p;
	bool use_previous = false;
	uint32_t current_kvno;
	uint32_t previous_kvno;
	uint32_t num_keys = 0;
	enum ndr_err_code ndr_err;
	int ret;
	unsigned int i;
	struct AuthenticationInformationArray *auth_array;
	struct timeval tv;
	NTTIME an_hour_ago;
	uint32_t *auth_kvno;
	bool preferr_current = false;
	uint32_t supported_enctypes = ENC_RC4_HMAC_MD5;
	struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
	NTSTATUS status;

	if (dsdb_functional_level(kdc_db_ctx->samdb) >= DS_DOMAIN_FUNCTION_2008) {
		supported_enctypes = ldb_msg_find_attr_as_uint(msg,
					"msDS-SupportedEncryptionTypes",
					supported_enctypes);
	}

	status = dsdb_trust_parse_tdo_info(mem_ctx, msg, &tdo);
	if (!NT_STATUS_IS_OK(status)) {
		krb5_clear_error_message(context);
		ret = ENOMEM;
		goto out;
	}

	if (!(tdo->trust_direction & direction)) {
		krb5_clear_error_message(context);
		ret = SDB_ERR_NOENTRY;
		goto out;
	}

	if (tdo->trust_type != LSA_TRUST_TYPE_UPLEVEL) {
		/*
		 * Only UPLEVEL domains support kerberos here,
		 * as we don't support LSA_TRUST_TYPE_MIT.
		 */
		krb5_clear_error_message(context);
		ret = SDB_ERR_NOENTRY;
		goto out;
	}

	if (tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_CROSS_ORGANIZATION) {
		/*
		 * We don't support selective authentication yet.
		 */
		krb5_clear_error_message(context);
		ret = SDB_ERR_NOENTRY;
		goto out;
	}

	if (tdo->domain_name.string == NULL) {
		krb5_clear_error_message(context);
		ret = SDB_ERR_NOENTRY;
		goto out;
	}
	partner_realm = strupper_talloc(mem_ctx, tdo->domain_name.string);
	if (partner_realm == NULL) {
		krb5_clear_error_message(context);
		ret = ENOMEM;
		goto out;
	}

	if (direction == INBOUND) {
		realm = our_realm;
		krbtgt_realm = partner_realm;

		password_val = ldb_msg_find_ldb_val(msg, "trustAuthIncoming");
	} else { /* OUTBOUND */
		realm = partner_realm;
		krbtgt_realm = our_realm;

		password_val = ldb_msg_find_ldb_val(msg, "trustAuthOutgoing");
	}

	if (password_val == NULL) {
		krb5_clear_error_message(context);
		ret = SDB_ERR_NOENTRY;
		goto out;
	}

	ndr_err = ndr_pull_struct_blob(password_val, mem_ctx, &password_blob,
				       (ndr_pull_flags_fn_t)ndr_pull_trustAuthInOutBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		krb5_clear_error_message(context);
		ret = EINVAL;
		goto out;
	}

	p = talloc_zero(mem_ctx, struct samba_kdc_entry);
	if (!p) {
		ret = ENOMEM;
		goto out;
	}

	p->is_trust = true;
	p->kdc_db_ctx = kdc_db_ctx;
	p->realm_dn = realm_dn;

	talloc_set_destructor(p, samba_kdc_entry_destructor);

	/* make sure we do not have bogus data in there */
	memset(&entry_ex->entry, 0, sizeof(struct sdb_entry));

	entry_ex->ctx = p;

	/* use 'whenCreated' */
	entry_ex->entry.created_by.time = ldb_msg_find_krb5time_ldap_time(msg, "whenCreated", 0);
	/* use 'kadmin' for now (needed by mit_samba) */
	ret = smb_krb5_make_principal(context,
				      &entry_ex->entry.created_by.principal,
				      realm, "kadmin", NULL);
	if (ret) {
		krb5_clear_error_message(context);
		goto out;
	}

	/*
	 * We always need to generate the canonicalized principal
	 * with the values of our database.
	 */
	ret = smb_krb5_make_principal(context, &entry_ex->entry.principal, realm,
				      "krbtgt", krbtgt_realm, NULL);
	if (ret) {
		krb5_clear_error_message(context);
		goto out;
	}
	smb_krb5_principal_set_type(context, entry_ex->entry.principal,
				    KRB5_NT_SRV_INST);

	entry_ex->entry.valid_start = NULL;

	/* we need to work out if we are going to use the current or
	 * the previous password hash.
	 * We base this on the kvno the client passes in. If the kvno
	 * passed in is equal to the current kvno in our database then
	 * we use the current structure. If it is the current kvno-1,
	 * then we use the previous substrucure.
	 */

	/*
	 * Windows preferrs the previous key for one hour.
	 */
	tv = timeval_current();
	if (tv.tv_sec > 3600) {
		tv.tv_sec -= 3600;
	}
	an_hour_ago = timeval_to_nttime(&tv);

	/* first work out the current kvno */
	current_kvno = 0;
	for (i=0; i < password_blob.count; i++) {
		struct AuthenticationInformation *a =
			&password_blob.current.array[i];

		if (a->LastUpdateTime <= an_hour_ago) {
			preferr_current = true;
		}

		if (a->AuthType == TRUST_AUTH_TYPE_VERSION) {
			current_kvno = a->AuthInfo.version.version;
		}
	}
	if (current_kvno == 0) {
		previous_kvno = 255;
	} else {
		previous_kvno = current_kvno - 1;
	}
	for (i=0; i < password_blob.count; i++) {
		struct AuthenticationInformation *a =
			&password_blob.previous.array[i];

		if (a->AuthType == TRUST_AUTH_TYPE_VERSION) {
			previous_kvno = a->AuthInfo.version.version;
		}
	}

	/* work out whether we will use the previous or current
	   password */
	if (password_blob.previous.count == 0) {
		/* there is no previous password */
		use_previous = false;
	} else if (!(flags & SDB_F_KVNO_SPECIFIED)) {
		/*
		 * If not specified we use the lowest kvno
		 * for the first hour after an update.
		 */
		if (preferr_current) {
			use_previous = false;
		} else if (previous_kvno < current_kvno) {
			use_previous = true;
		} else {
			use_previous = false;
		}
	} else if (kvno == current_kvno) {
		/*
		 * Exact match ...
		 */
		use_previous = false;
	} else if (kvno == previous_kvno) {
		/*
		 * Exact match ...
		 */
		use_previous = true;
	} else {
		/*
		 * Fallback to the current one for anything else
		 */
		use_previous = false;
	}

	if (use_previous) {
		auth_array = &password_blob.previous;
		auth_kvno = &previous_kvno;
	} else {
		auth_array = &password_blob.current;
		auth_kvno = &current_kvno;
	}

	/* use the kvno the client specified, if available */
	if (flags & SDB_F_KVNO_SPECIFIED) {
		entry_ex->entry.kvno = kvno;
	} else {
		entry_ex->entry.kvno = *auth_kvno;
	}

	for (i=0; i < auth_array->count; i++) {
		if (auth_array->array[i].AuthType == TRUST_AUTH_TYPE_CLEAR) {
			bool ok;

			password_utf16 = data_blob_const(auth_array->array[i].AuthInfo.clear.password,
							 auth_array->array[i].AuthInfo.clear.size);
			if (password_utf16.length == 0) {
				break;
			}

			if (supported_enctypes & ENC_RC4_HMAC_MD5) {
				mdfour(_password_hash.hash, password_utf16.data, password_utf16.length);
				if (password_hash == NULL) {
					num_keys += 1;
				}
				password_hash = &_password_hash;
			}

			if (!(supported_enctypes & (ENC_HMAC_SHA1_96_AES128|ENC_HMAC_SHA1_96_AES256))) {
				break;
			}

			ok = convert_string_talloc(mem_ctx,
						   CH_UTF16MUNGED, CH_UTF8,
						   password_utf16.data,
						   password_utf16.length,
						   (void *)&password_utf8.data,
						   &password_utf8.length);
			if (!ok) {
				krb5_clear_error_message(context);
				ret = ENOMEM;
				goto out;
			}

			if (supported_enctypes & ENC_HMAC_SHA1_96_AES128) {
				num_keys += 1;
			}
			if (supported_enctypes & ENC_HMAC_SHA1_96_AES256) {
				num_keys += 1;
			}
			break;
		} else if (auth_array->array[i].AuthType == TRUST_AUTH_TYPE_NT4OWF) {
			if (supported_enctypes & ENC_RC4_HMAC_MD5) {
				password_hash = &auth_array->array[i].AuthInfo.nt4owf.password;
				num_keys += 1;
			}
		}
	}

	/* Must have found a cleartext or MD4 password */
	if (num_keys == 0) {
		DEBUG(1,(__location__ ": no usable key found\n"));
		krb5_clear_error_message(context);
		ret = SDB_ERR_NOENTRY;
		goto out;
	}

	entry_ex->entry.keys.val = calloc(num_keys, sizeof(struct sdb_key));
	if (entry_ex->entry.keys.val == NULL) {
		krb5_clear_error_message(context);
		ret = ENOMEM;
		goto out;
	}

	if (password_utf8.length != 0) {
		struct sdb_key key = {};
		krb5_const_principal salt_principal = entry_ex->entry.principal;
		krb5_data salt;
		krb5_data cleartext_data;

		cleartext_data.data = discard_const_p(char, password_utf8.data);
		cleartext_data.length = password_utf8.length;

		ret = smb_krb5_get_pw_salt(context,
					   salt_principal,
					   &salt);
		if (ret != 0) {
			goto out;
		}

		if (supported_enctypes & ENC_HMAC_SHA1_96_AES256) {
			ret = smb_krb5_create_key_from_string(context,
							      salt_principal,
							      &salt,
							      &cleartext_data,
							      ENCTYPE_AES256_CTS_HMAC_SHA1_96,
							      &key.key);
			if (ret != 0) {
				smb_krb5_free_data_contents(context, &salt);
				goto out;
			}

			entry_ex->entry.keys.val[entry_ex->entry.keys.len] = key;
			entry_ex->entry.keys.len++;
		}

		if (supported_enctypes & ENC_HMAC_SHA1_96_AES128) {
			ret = smb_krb5_create_key_from_string(context,
							      salt_principal,
							      &salt,
							      &cleartext_data,
							      ENCTYPE_AES128_CTS_HMAC_SHA1_96,
							      &key.key);
			if (ret != 0) {
				smb_krb5_free_data_contents(context, &salt);
				goto out;
			}

			entry_ex->entry.keys.val[entry_ex->entry.keys.len] = key;
			entry_ex->entry.keys.len++;
		}

		smb_krb5_free_data_contents(context, &salt);
	}

	if (password_hash != NULL) {
		struct sdb_key key = {};

		ret = smb_krb5_keyblock_init_contents(context,
						      ENCTYPE_ARCFOUR_HMAC,
						      password_hash->hash,
						      sizeof(password_hash->hash),
						      &key.key);
		if (ret != 0) {
			goto out;
		}

		entry_ex->entry.keys.val[entry_ex->entry.keys.len] = key;
		entry_ex->entry.keys.len++;
	}

	entry_ex->entry.flags = int2SDBFlags(0);
	entry_ex->entry.flags.immutable = 1;
	entry_ex->entry.flags.invalid = 0;
	entry_ex->entry.flags.server = 1;
	entry_ex->entry.flags.require_preauth = 1;

	entry_ex->entry.pw_end = NULL;

	entry_ex->entry.max_life = NULL;

	entry_ex->entry.max_renew = NULL;

	/* Match Windows behavior and allow forwardable flag in cross-realm. */
	entry_ex->entry.flags.forwardable = 1;

	ret = samba_kdc_sort_encryption_keys(entry_ex);
	if (ret != 0) {
		krb5_clear_error_message(context);
		ret = ENOMEM;
		goto out;
	}

	p->msg = talloc_steal(p, msg);

out:
	TALLOC_FREE(partner_realm);

	if (ret != 0) {
		/* This doesn't free ent itself, that is for the eventual caller to do */
		sdb_free_entry(entry_ex);
	} else {
		talloc_steal(kdc_db_ctx, entry_ex->ctx);
	}

	return ret;

}

static krb5_error_code samba_kdc_lookup_trust(krb5_context context, struct ldb_context *ldb_ctx,
					TALLOC_CTX *mem_ctx,
					const char *realm,
					struct ldb_dn *realm_dn,
					struct ldb_message **pmsg)
{
	NTSTATUS status;
	const char * const *attrs = trust_attrs;

	status = dsdb_trust_search_tdo(ldb_ctx, realm, realm,
				       attrs, mem_ctx, pmsg);
	if (NT_STATUS_IS_OK(status)) {
		return 0;
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		return SDB_ERR_NOENTRY;
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MEMORY)) {
		int ret = ENOMEM;
		krb5_set_error_message(context, ret, "get_sam_result_trust: out of memory");
		return ret;
	} else {
		int ret = EINVAL;
		krb5_set_error_message(context, ret, "get_sam_result_trust: %s", nt_errstr(status));
		return ret;
	}
}

static krb5_error_code samba_kdc_lookup_client(krb5_context context,
						struct samba_kdc_db_context *kdc_db_ctx,
						TALLOC_CTX *mem_ctx,
						krb5_const_principal principal,
						const char **attrs,
						struct ldb_dn **realm_dn,
						struct ldb_message **msg)
{
	NTSTATUS nt_status;
	char *principal_string = NULL;

	if (smb_krb5_principal_get_type(context, principal) == KRB5_NT_ENTERPRISE_PRINCIPAL) {
		principal_string = smb_krb5_principal_get_comp_string(mem_ctx, context,
								      principal, 0);
		if (principal_string == NULL) {
			return ENOMEM;
		}
	} else {
		char *principal_string_m = NULL;
		krb5_error_code ret;

		ret = krb5_unparse_name(context, principal, &principal_string_m);
		if (ret != 0) {
			return ret;
		}

		principal_string = talloc_strdup(mem_ctx, principal_string_m);
		SAFE_FREE(principal_string_m);
		if (principal_string == NULL) {
			return ENOMEM;
		}
	}

	nt_status = sam_get_results_principal(kdc_db_ctx->samdb,
					      mem_ctx, principal_string, attrs,
					      realm_dn, msg);
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_SUCH_USER)) {
		krb5_principal fallback_principal = NULL;
		unsigned int num_comp;
		char *fallback_realm = NULL;
		char *fallback_account = NULL;
		krb5_error_code ret;

		ret = krb5_parse_name(context, principal_string,
				      &fallback_principal);
		TALLOC_FREE(principal_string);
		if (ret != 0) {
			return ret;
		}

		num_comp = krb5_princ_size(context, fallback_principal);
		fallback_realm = smb_krb5_principal_get_realm(
			mem_ctx, context, fallback_principal);
		if (fallback_realm == NULL) {
			krb5_free_principal(context, fallback_principal);
			return ENOMEM;
		}

		if (num_comp == 1) {
			size_t len;

			fallback_account = smb_krb5_principal_get_comp_string(mem_ctx,
						context, fallback_principal, 0);
			if (fallback_account == NULL) {
				krb5_free_principal(context, fallback_principal);
				TALLOC_FREE(fallback_realm);
				return ENOMEM;
			}

			len = strlen(fallback_account);
			if (len >= 2 && fallback_account[len - 1] == '$') {
				TALLOC_FREE(fallback_account);
			}
		}
		krb5_free_principal(context, fallback_principal);
		fallback_principal = NULL;

		if (fallback_account != NULL) {
			char *with_dollar;

			with_dollar = talloc_asprintf(mem_ctx, "%s$",
						     fallback_account);
			if (with_dollar == NULL) {
				TALLOC_FREE(fallback_realm);
				return ENOMEM;
			}
			TALLOC_FREE(fallback_account);

			ret = smb_krb5_make_principal(context,
						      &fallback_principal,
						      fallback_realm,
						      with_dollar, NULL);
			TALLOC_FREE(with_dollar);
			if (ret != 0) {
				TALLOC_FREE(fallback_realm);
				return ret;
			}
		}
		TALLOC_FREE(fallback_realm);

		if (fallback_principal != NULL) {
			char *fallback_string = NULL;

			ret = krb5_unparse_name(context,
						fallback_principal,
						&fallback_string);
			if (ret != 0) {
				krb5_free_principal(context, fallback_principal);
				return ret;
			}

			nt_status = sam_get_results_principal(kdc_db_ctx->samdb,
							      mem_ctx,
							      fallback_string,
							      attrs,
							      realm_dn, msg);
			SAFE_FREE(fallback_string);
		}
		krb5_free_principal(context, fallback_principal);
		fallback_principal = NULL;
	}
	TALLOC_FREE(principal_string);

	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_SUCH_USER)) {
		return SDB_ERR_NOENTRY;
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_MEMORY)) {
		return ENOMEM;
	} else if (!NT_STATUS_IS_OK(nt_status)) {
		return EINVAL;
	}

	return 0;
}

static krb5_error_code samba_kdc_fetch_client(krb5_context context,
					       struct samba_kdc_db_context *kdc_db_ctx,
					       TALLOC_CTX *mem_ctx,
					       krb5_const_principal principal,
					       unsigned flags,
					       struct sdb_entry_ex *entry_ex) {
	struct ldb_dn *realm_dn;
	krb5_error_code ret;
	struct ldb_message *msg = NULL;

	ret = samba_kdc_lookup_client(context, kdc_db_ctx,
				      mem_ctx, principal, user_attrs,
				      &realm_dn, &msg);
	if (ret != 0) {
		return ret;
	}

	ret = samba_kdc_message2entry(context, kdc_db_ctx, mem_ctx,
				      principal, SAMBA_KDC_ENT_TYPE_CLIENT,
				      flags,
				      realm_dn, msg, entry_ex);
	return ret;
}

static krb5_error_code samba_kdc_fetch_krbtgt(krb5_context context,
					      struct samba_kdc_db_context *kdc_db_ctx,
					      TALLOC_CTX *mem_ctx,
					      krb5_const_principal principal,
					      unsigned flags,
					      uint32_t kvno,
					      struct sdb_entry_ex *entry_ex)
{
	struct loadparm_context *lp_ctx = kdc_db_ctx->lp_ctx;
	krb5_error_code ret;
	struct ldb_message *msg = NULL;
	struct ldb_dn *realm_dn = ldb_get_default_basedn(kdc_db_ctx->samdb);
	char *realm_from_princ;
	char *realm_princ_comp = smb_krb5_principal_get_comp_string(mem_ctx, context, principal, 1);

	realm_from_princ = smb_krb5_principal_get_realm(
		mem_ctx, context, principal);
	if (realm_from_princ == NULL) {
		/* can't happen */
		return SDB_ERR_NOENTRY;
	}

	if (krb5_princ_size(context, principal) != 2
	    || (principal_comp_strcmp(context, principal, 0, KRB5_TGS_NAME) != 0)) {
		/* Not a krbtgt */
		return SDB_ERR_NOENTRY;
	}

	/* krbtgt case.  Either us or a trusted realm */

	if (lpcfg_is_my_domain_or_realm(lp_ctx, realm_from_princ)
	    && lpcfg_is_my_domain_or_realm(lp_ctx, realm_princ_comp)) {
		/* us, or someone quite like us */
 		/* Cludge, cludge cludge.  If the realm part of krbtgt/realm,
 		 * is in our db, then direct the caller at our primary
 		 * krbtgt */

		int lret;
		unsigned int krbtgt_number;
		/* w2k8r2 sometimes gives us a kvno of 255 for inter-domain
		   trust tickets. We don't yet know what this means, but we do
		   seem to need to treat it as unspecified */
		if (flags & SDB_F_KVNO_SPECIFIED) {
			krbtgt_number = SAMBA_KVNO_GET_KRBTGT(kvno);
			if (kdc_db_ctx->rodc) {
				if (krbtgt_number != kdc_db_ctx->my_krbtgt_number) {
					return SDB_ERR_NOT_FOUND_HERE;
				}
			}
		} else {
			krbtgt_number = kdc_db_ctx->my_krbtgt_number;
		}

		if (krbtgt_number == kdc_db_ctx->my_krbtgt_number) {
			lret = dsdb_search_one(kdc_db_ctx->samdb, mem_ctx,
					       &msg, kdc_db_ctx->krbtgt_dn, LDB_SCOPE_BASE,
					       krbtgt_attrs, DSDB_SEARCH_NO_GLOBAL_CATALOG,
					       "(objectClass=user)");
		} else {
			/* We need to look up an RODC krbtgt (perhaps
			 * ours, if we are an RODC, perhaps another
			 * RODC if we are a read-write DC */
			lret = dsdb_search_one(kdc_db_ctx->samdb, mem_ctx,
					       &msg, realm_dn, LDB_SCOPE_SUBTREE,
					       krbtgt_attrs,
					       DSDB_SEARCH_SHOW_EXTENDED_DN | DSDB_SEARCH_NO_GLOBAL_CATALOG,
					       "(&(objectClass=user)(msDS-SecondaryKrbTgtNumber=%u))", (unsigned)(krbtgt_number));
		}

		if (lret == LDB_ERR_NO_SUCH_OBJECT) {
			krb5_warnx(context, "samba_kdc_fetch: could not find KRBTGT number %u in DB!",
				   (unsigned)(krbtgt_number));
			krb5_set_error_message(context, SDB_ERR_NOENTRY,
					       "samba_kdc_fetch: could not find KRBTGT number %u in DB!",
					       (unsigned)(krbtgt_number));
			return SDB_ERR_NOENTRY;
		} else if (lret != LDB_SUCCESS) {
			krb5_warnx(context, "samba_kdc_fetch: could not find KRBTGT number %u in DB!",
				   (unsigned)(krbtgt_number));
			krb5_set_error_message(context, SDB_ERR_NOENTRY,
					       "samba_kdc_fetch: could not find KRBTGT number %u in DB!",
					       (unsigned)(krbtgt_number));
			return SDB_ERR_NOENTRY;
		}

		ret = samba_kdc_message2entry(context, kdc_db_ctx, mem_ctx,
					      principal, SAMBA_KDC_ENT_TYPE_KRBTGT,
					      flags, realm_dn, msg, entry_ex);
		if (ret != 0) {
			krb5_warnx(context, "samba_kdc_fetch: self krbtgt message2entry failed");
		}
		return ret;

	} else {
		enum trust_direction direction = UNKNOWN;
		const char *realm = NULL;

		/* Either an inbound or outbound trust */

		if (strcasecmp(lpcfg_realm(lp_ctx), realm_from_princ) == 0) {
			/* look for inbound trust */
			direction = INBOUND;
			realm = realm_princ_comp;
		} else if (principal_comp_strcasecmp(context, principal, 1, lpcfg_realm(lp_ctx)) == 0) {
			/* look for outbound trust */
			direction = OUTBOUND;
			realm = realm_from_princ;
		} else {
			krb5_warnx(context, "samba_kdc_fetch: not our realm for trusts ('%s', '%s')",
				   realm_from_princ,
				   realm_princ_comp);
			krb5_set_error_message(context, SDB_ERR_NOENTRY, "samba_kdc_fetch: not our realm for trusts ('%s', '%s')",
					       realm_from_princ,
					       realm_princ_comp);
			return SDB_ERR_NOENTRY;
		}

		/* Trusted domains are under CN=system */

		ret = samba_kdc_lookup_trust(context, kdc_db_ctx->samdb,
				       mem_ctx,
				       realm, realm_dn, &msg);

		if (ret != 0) {
			krb5_warnx(context, "samba_kdc_fetch: could not find principal in DB");
			krb5_set_error_message(context, ret, "samba_kdc_fetch: could not find principal in DB");
			return ret;
		}

		ret = samba_kdc_trust_message2entry(context, kdc_db_ctx, mem_ctx,
						    principal, direction,
						    realm_dn, flags, kvno, msg, entry_ex);
		if (ret != 0) {
			krb5_warnx(context, "samba_kdc_fetch: trust_message2entry failed for %s",
				   ldb_dn_get_linearized(msg->dn));
			krb5_set_error_message(context, ret, "samba_kdc_fetch: "
					       "trust_message2entry failed for %s",
					       ldb_dn_get_linearized(msg->dn));
		}
		return ret;
	}

}

static krb5_error_code samba_kdc_lookup_server(krb5_context context,
					       struct samba_kdc_db_context *kdc_db_ctx,
					       TALLOC_CTX *mem_ctx,
					       krb5_const_principal principal,
					       unsigned flags,
					       const char **attrs,
					       struct ldb_dn **realm_dn,
					       struct ldb_message **msg)
{
	krb5_error_code ret;
	if ((smb_krb5_principal_get_type(context, principal) != KRB5_NT_ENTERPRISE_PRINCIPAL)
	    && krb5_princ_size(context, principal) >= 2) {
		/* 'normal server' case */
		int ldb_ret;
		NTSTATUS nt_status;
		struct ldb_dn *user_dn;
		char *principal_string;

		ret = krb5_unparse_name_flags(context, principal,
					      KRB5_PRINCIPAL_UNPARSE_NO_REALM,
					      &principal_string);
		if (ret != 0) {
			return ret;
		}

		/* At this point we may find the host is known to be
		 * in a different realm, so we should generate a
		 * referral instead */
		nt_status = crack_service_principal_name(kdc_db_ctx->samdb,
							 mem_ctx, principal_string,
							 &user_dn, realm_dn);
		free(principal_string);

		if (!NT_STATUS_IS_OK(nt_status)) {
			return SDB_ERR_NOENTRY;
		}

		ldb_ret = dsdb_search_one(kdc_db_ctx->samdb,
					  mem_ctx,
					  msg, user_dn, LDB_SCOPE_BASE,
					  attrs,
					  DSDB_SEARCH_SHOW_EXTENDED_DN | DSDB_SEARCH_NO_GLOBAL_CATALOG,
					  "(objectClass=*)");
		if (ldb_ret != LDB_SUCCESS) {
			return SDB_ERR_NOENTRY;
		}
		return 0;
	} else if (!(flags & SDB_F_FOR_AS_REQ)
		   && smb_krb5_principal_get_type(context, principal) == KRB5_NT_ENTERPRISE_PRINCIPAL) {
		/*
		 * The behaviour of accepting an
		 * KRB5_NT_ENTERPRISE_PRINCIPAL server principal
		 * containing a UPN only applies to TGS-REQ packets,
		 * not AS-REQ packets.
		 */
		return samba_kdc_lookup_client(context, kdc_db_ctx,
					       mem_ctx, principal, attrs,
					       realm_dn, msg);
	} else {
		/*
		 * This case is for:
		 *  - the AS-REQ, where we only accept
		 *    samAccountName based lookups for the server, no
		 *    matter if the name is an
		 *    KRB5_NT_ENTERPRISE_PRINCIPAL or not
		 *  - for the TGS-REQ when we are not given an
		 *    KRB5_NT_ENTERPRISE_PRINCIPAL, which also must
		 *    only lookup samAccountName based names.
		 */
		int lret;
		char *short_princ;
		krb5_principal enterprise_principal = NULL;
		krb5_const_principal used_principal = NULL;
		char *name1 = NULL;
		size_t len1 = 0;
		char *filter = NULL;

		if (smb_krb5_principal_get_type(context, principal) == KRB5_NT_ENTERPRISE_PRINCIPAL) {
			char *str = NULL;
			/* Need to reparse the enterprise principal to find the real target */
			if (krb5_princ_size(context, principal) != 1) {
				ret = KRB5_PARSE_MALFORMED;
				krb5_set_error_message(context, ret, "samba_kdc_lookup_server: request for an "
						       "enterprise principal with wrong (%d) number of components",
						       krb5_princ_size(context, principal));
				return ret;
			}
			str = smb_krb5_principal_get_comp_string(mem_ctx, context, principal, 0);
			if (str == NULL) {
				return KRB5_PARSE_MALFORMED;
			}
			ret = krb5_parse_name(context, str,
					      &enterprise_principal);
			talloc_free(str);
			if (ret) {
				return ret;
			}
			used_principal = enterprise_principal;
		} else {
			used_principal = principal;
		}

		/* server as client principal case, but we must not lookup userPrincipalNames */
		*realm_dn = ldb_get_default_basedn(kdc_db_ctx->samdb);

		/* TODO: Check if it is our realm, otherwise give referral */

		ret = krb5_unparse_name_flags(context, used_principal,
					      KRB5_PRINCIPAL_UNPARSE_NO_REALM |
					      KRB5_PRINCIPAL_UNPARSE_DISPLAY,
					      &short_princ);
		used_principal = NULL;
		krb5_free_principal(context, enterprise_principal);
		enterprise_principal = NULL;

		if (ret != 0) {
			krb5_set_error_message(context, ret, "samba_kdc_lookup_principal: could not parse principal");
			krb5_warnx(context, "samba_kdc_lookup_principal: could not parse principal");
			return ret;
		}

		name1 = ldb_binary_encode_string(mem_ctx, short_princ);
		SAFE_FREE(short_princ);
		if (name1 == NULL) {
			return ENOMEM;
		}
		len1 = strlen(name1);
		if (len1 >= 1 && name1[len1 - 1] != '$') {
			filter = talloc_asprintf(mem_ctx,
					"(&(objectClass=user)(|(samAccountName=%s)(samAccountName=%s$)))",
					name1, name1);
			if (filter == NULL) {
				return ENOMEM;
			}
		} else {
			filter = talloc_asprintf(mem_ctx,
					"(&(objectClass=user)(samAccountName=%s))",
					name1);
			if (filter == NULL) {
				return ENOMEM;
			}
		}

		lret = dsdb_search_one(kdc_db_ctx->samdb, mem_ctx, msg,
				       *realm_dn, LDB_SCOPE_SUBTREE,
				       attrs,
				       DSDB_SEARCH_SHOW_EXTENDED_DN | DSDB_SEARCH_NO_GLOBAL_CATALOG,
				       "%s", filter);
		if (lret == LDB_ERR_NO_SUCH_OBJECT) {
			DEBUG(10, ("Failed to find an entry for %s filter:%s\n",
				  name1, filter));
			return SDB_ERR_NOENTRY;
		}
		if (lret == LDB_ERR_CONSTRAINT_VIOLATION) {
			DEBUG(10, ("Failed to find unique entry for %s filter:%s\n",
				  name1, filter));
			return SDB_ERR_NOENTRY;
		}
		if (lret != LDB_SUCCESS) {
			DEBUG(0, ("Failed single search for %s - %s\n",
				  name1, ldb_errstring(kdc_db_ctx->samdb)));
			return SDB_ERR_NOENTRY;
		}
		return 0;
	}
	return SDB_ERR_NOENTRY;
}



static krb5_error_code samba_kdc_fetch_server(krb5_context context,
					      struct samba_kdc_db_context *kdc_db_ctx,
					      TALLOC_CTX *mem_ctx,
					      krb5_const_principal principal,
					      unsigned flags,
					      struct sdb_entry_ex *entry_ex)
{
	krb5_error_code ret;
	struct ldb_dn *realm_dn;
	struct ldb_message *msg;

	ret = samba_kdc_lookup_server(context, kdc_db_ctx, mem_ctx, principal,
				      flags, server_attrs, &realm_dn, &msg);
	if (ret != 0) {
		return ret;
	}

	ret = samba_kdc_message2entry(context, kdc_db_ctx, mem_ctx,
				      principal, SAMBA_KDC_ENT_TYPE_SERVER,
				      flags,
				      realm_dn, msg, entry_ex);
	if (ret != 0) {
		krb5_warnx(context, "samba_kdc_fetch: message2entry failed");
	}

	return ret;
}

static krb5_error_code samba_kdc_lookup_realm(krb5_context context,
					      struct samba_kdc_db_context *kdc_db_ctx,
					      TALLOC_CTX *mem_ctx,
					      krb5_const_principal principal,
					      unsigned flags,
					      struct sdb_entry_ex *entry_ex)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	krb5_error_code ret;
	bool check_realm = false;
	const char *realm = NULL;
	struct dsdb_trust_routing_table *trt = NULL;
	const struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
	unsigned int num_comp;
	bool ok;
	char *upper = NULL;

	num_comp = krb5_princ_size(context, principal);

	if (flags & SDB_F_GET_CLIENT) {
		if (flags & SDB_F_FOR_AS_REQ) {
			check_realm = true;
		}
	}
	if (flags & SDB_F_GET_SERVER) {
		if (flags & SDB_F_FOR_TGS_REQ) {
			check_realm = true;
		}
	}

	if (!check_realm) {
		TALLOC_FREE(frame);
		return 0;
	}

	realm = smb_krb5_principal_get_realm(frame, context, principal);
	if (realm == NULL) {
		TALLOC_FREE(frame);
		return ENOMEM;
	}

	/*
	 * The requested realm needs to be our own
	 */
	ok = lpcfg_is_my_domain_or_realm(kdc_db_ctx->lp_ctx, realm);
	if (!ok) {
		/*
		 * The request is not for us...
		 */
		TALLOC_FREE(frame);
		return SDB_ERR_NOENTRY;
	}

	if (smb_krb5_principal_get_type(context, principal) == KRB5_NT_ENTERPRISE_PRINCIPAL) {
		char *principal_string = NULL;
		krb5_principal enterprise_principal = NULL;
		char *enterprise_realm = NULL;

		if (num_comp != 1) {
			TALLOC_FREE(frame);
			return SDB_ERR_NOENTRY;
		}

		principal_string = smb_krb5_principal_get_comp_string(frame, context,
								      principal, 0);
		if (principal_string == NULL) {
			TALLOC_FREE(frame);
			return ENOMEM;
		}

		ret = krb5_parse_name(context, principal_string,
				      &enterprise_principal);
		TALLOC_FREE(principal_string);
		if (ret) {
			TALLOC_FREE(frame);
			return ret;
		}

		enterprise_realm = smb_krb5_principal_get_realm(
			frame, context, enterprise_principal);
		krb5_free_principal(context, enterprise_principal);
		if (enterprise_realm != NULL) {
			realm = enterprise_realm;
		}
	}

	if (flags & SDB_F_GET_SERVER) {
		char *service_realm = NULL;

		ret = principal_comp_strcmp(context, principal, 0, KRB5_TGS_NAME);
		if (ret == 0) {
			/*
			 * we need to search krbtgt/ locally
			 */
			TALLOC_FREE(frame);
			return 0;
		}

		/*
		 * We need to check the last component against the routing table.
		 *
		 * Note this works only with 2 or 3 component principals, e.g:
		 *
		 * servicePrincipalName: ldap/W2K8R2-219.bla.base
		 * servicePrincipalName: ldap/W2K8R2-219.bla.base/bla.base
		 * servicePrincipalName: ldap/W2K8R2-219.bla.base/ForestDnsZones.bla.base
		 * servicePrincipalName: ldap/W2K8R2-219.bla.base/DomainDnsZones.bla.base
		 */

		if (num_comp == 2 || num_comp == 3) {
			service_realm = smb_krb5_principal_get_comp_string(frame,
									   context,
									   principal,
									   num_comp - 1);
		}

		if (service_realm != NULL) {
			realm = service_realm;
		}
	}

	ok = lpcfg_is_my_domain_or_realm(kdc_db_ctx->lp_ctx, realm);
	if (ok) {
		/*
		 * skip the expensive routing lookup
		 */
		TALLOC_FREE(frame);
		return 0;
	}

	status = dsdb_trust_routing_table_load(kdc_db_ctx->samdb,
					       frame, &trt);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return EINVAL;
	}

	tdo = dsdb_trust_routing_by_name(trt, realm);
	if (tdo == NULL) {
		/*
		 * This principal has to be local
		 */
		TALLOC_FREE(frame);
		return 0;
	}

	if (tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST) {
		/*
		 * TODO: handle the routing within the forest
		 *
		 * This should likely be handled in
		 * samba_kdc_message2entry() in case we're
		 * a global catalog. We'd need to check
		 * if realm_dn is our own domain and derive
		 * the dns domain name from realm_dn and check that
		 * against the routing table or fallback to
		 * the tdo we found here.
		 *
		 * But for now we don't support multiple domains
		 * in our forest correctly anyway.
		 *
		 * Just search in our local database.
		 */
		TALLOC_FREE(frame);
		return 0;
	}

	ZERO_STRUCT(entry_ex->entry);

	ret = krb5_copy_principal(context, principal,
				  &entry_ex->entry.principal);
	if (ret) {
		TALLOC_FREE(frame);
		return ret;
	}

	upper = strupper_talloc(frame, tdo->domain_name.string);
	if (upper == NULL) {
		TALLOC_FREE(frame);
		return ENOMEM;
	}

	ret = smb_krb5_principal_set_realm(context,
					   entry_ex->entry.principal,
					   upper);
	if (ret) {
		TALLOC_FREE(frame);
		return ret;
	}

	TALLOC_FREE(frame);
	return SDB_ERR_WRONG_REALM;
}

krb5_error_code samba_kdc_fetch(krb5_context context,
				struct samba_kdc_db_context *kdc_db_ctx,
				krb5_const_principal principal,
				unsigned flags,
				krb5_kvno kvno,
				struct sdb_entry_ex *entry_ex)
{
	krb5_error_code ret = SDB_ERR_NOENTRY;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_named(kdc_db_ctx, 0, "samba_kdc_fetch context");
	if (!mem_ctx) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "samba_kdc_fetch: talloc_named() failed!");
		return ret;
	}

	ret = samba_kdc_lookup_realm(context, kdc_db_ctx, mem_ctx,
				     principal, flags, entry_ex);
	if (ret != 0) {
		goto done;
	}

	ret = SDB_ERR_NOENTRY;

	if (flags & SDB_F_GET_CLIENT) {
		ret = samba_kdc_fetch_client(context, kdc_db_ctx, mem_ctx, principal, flags, entry_ex);
		if (ret != SDB_ERR_NOENTRY) goto done;
	}
	if (flags & SDB_F_GET_SERVER) {
		/* krbtgt fits into this situation for trusted realms, and for resolving different versions of our own realm name */
		ret = samba_kdc_fetch_krbtgt(context, kdc_db_ctx, mem_ctx, principal, flags, kvno, entry_ex);
		if (ret != SDB_ERR_NOENTRY) goto done;

		/* We return 'no entry' if it does not start with krbtgt/, so move to the common case quickly */
		ret = samba_kdc_fetch_server(context, kdc_db_ctx, mem_ctx, principal, flags, entry_ex);
		if (ret != SDB_ERR_NOENTRY) goto done;
	}
	if (flags & SDB_F_GET_KRBTGT) {
		ret = samba_kdc_fetch_krbtgt(context, kdc_db_ctx, mem_ctx, principal, flags, kvno, entry_ex);
		if (ret != SDB_ERR_NOENTRY) goto done;
	}

done:
	talloc_free(mem_ctx);
	return ret;
}

struct samba_kdc_seq {
	unsigned int index;
	unsigned int count;
	struct ldb_message **msgs;
	struct ldb_dn *realm_dn;
};

static krb5_error_code samba_kdc_seq(krb5_context context,
				     struct samba_kdc_db_context *kdc_db_ctx,
				     struct sdb_entry_ex *entry)
{
	krb5_error_code ret;
	struct samba_kdc_seq *priv = kdc_db_ctx->seq_ctx;
	const char *realm = lpcfg_realm(kdc_db_ctx->lp_ctx);
	struct ldb_message *msg = NULL;
	const char *sAMAccountName = NULL;
	krb5_principal principal = NULL;
	TALLOC_CTX *mem_ctx;

	if (!priv) {
		return SDB_ERR_NOENTRY;
	}

	mem_ctx = talloc_named(priv, 0, "samba_kdc_seq context");

	if (!mem_ctx) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "samba_kdc_seq: talloc_named() failed!");
		return ret;
	}

	while (priv->index < priv->count) {
		msg = priv->msgs[priv->index++];

		sAMAccountName = ldb_msg_find_attr_as_string(msg, "sAMAccountName", NULL);
		if (sAMAccountName != NULL) {
			break;
		}
	}

	if (sAMAccountName == NULL) {
		ret = SDB_ERR_NOENTRY;
		goto out;
	}

	ret = smb_krb5_make_principal(context, &principal,
				      realm, sAMAccountName, NULL);
	if (ret != 0) {
		goto out;
	}

	ret = samba_kdc_message2entry(context, kdc_db_ctx, mem_ctx,
				      principal, SAMBA_KDC_ENT_TYPE_ANY,
				      SDB_F_ADMIN_DATA|SDB_F_GET_ANY,
				      priv->realm_dn, msg, entry);

out:
	if (principal != NULL) {
		krb5_free_principal(context, principal);
	}

	if (ret != 0) {
		TALLOC_FREE(priv);
		kdc_db_ctx->seq_ctx = NULL;
	} else {
		talloc_free(mem_ctx);
	}

	return ret;
}

krb5_error_code samba_kdc_firstkey(krb5_context context,
				   struct samba_kdc_db_context *kdc_db_ctx,
				   struct sdb_entry_ex *entry)
{
	struct ldb_context *ldb_ctx = kdc_db_ctx->samdb;
	struct samba_kdc_seq *priv = kdc_db_ctx->seq_ctx;
	char *realm;
	struct ldb_result *res = NULL;
	krb5_error_code ret;
	TALLOC_CTX *mem_ctx;
	int lret;

	if (priv) {
		TALLOC_FREE(priv);
		kdc_db_ctx->seq_ctx = NULL;
	}

	priv = (struct samba_kdc_seq *) talloc(kdc_db_ctx, struct samba_kdc_seq);
	if (!priv) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "talloc: out of memory");
		return ret;
	}

	priv->index = 0;
	priv->msgs = NULL;
	priv->realm_dn = ldb_get_default_basedn(ldb_ctx);
	priv->count = 0;

	mem_ctx = talloc_named(priv, 0, "samba_kdc_firstkey context");

	if (!mem_ctx) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "samba_kdc_firstkey: talloc_named() failed!");
		return ret;
	}

	ret = krb5_get_default_realm(context, &realm);
	if (ret != 0) {
		TALLOC_FREE(priv);
		return ret;
	}
	krb5_free_default_realm(context, realm);

	lret = dsdb_search(ldb_ctx, priv, &res,
			   priv->realm_dn, LDB_SCOPE_SUBTREE, user_attrs,
			   DSDB_SEARCH_NO_GLOBAL_CATALOG,
			   "(objectClass=user)");

	if (lret != LDB_SUCCESS) {
		TALLOC_FREE(priv);
		return SDB_ERR_NOENTRY;
	}

	priv->count = res->count;
	priv->msgs = talloc_steal(priv, res->msgs);
	talloc_free(res);

	kdc_db_ctx->seq_ctx = priv;

	ret = samba_kdc_seq(context, kdc_db_ctx, entry);

	if (ret != 0) {
		TALLOC_FREE(priv);
		kdc_db_ctx->seq_ctx = NULL;
	} else {
		talloc_free(mem_ctx);
	}
	return ret;
}

krb5_error_code samba_kdc_nextkey(krb5_context context,
				  struct samba_kdc_db_context *kdc_db_ctx,
				  struct sdb_entry_ex *entry)
{
	return samba_kdc_seq(context, kdc_db_ctx, entry);
}

/* Check if a given entry may delegate or do s4u2self to this target principal
 *
 * The safest way to determine 'self' is to check the DB record made at
 * the time the principal was presented to the KDC.
 */
krb5_error_code
samba_kdc_check_s4u2self(krb5_context context,
			 struct samba_kdc_entry *skdc_entry_client,
			 struct samba_kdc_entry *skdc_entry_server_target)
{
	struct dom_sid *orig_sid;
	struct dom_sid *target_sid;
	TALLOC_CTX *frame = talloc_stackframe();

	orig_sid = samdb_result_dom_sid(frame,
					skdc_entry_client->msg,
					"objectSid");
	target_sid = samdb_result_dom_sid(frame,
					  skdc_entry_server_target->msg,
					  "objectSid");

	/*
	 * Allow delegation to the same record (representing a
	 * principal), even if by a different name.  The easy and safe
	 * way to prove this is by SID comparison
	 */
	if (!(orig_sid && target_sid && dom_sid_equal(orig_sid, target_sid))) {
		talloc_free(frame);
		return KRB5KDC_ERR_BADOPTION;
	}

	talloc_free(frame);
	return 0;
}

/* Certificates printed by a the Certificate Authority might have a
 * slightly different form of the user principal name to that in the
 * database.  Allow a mismatch where they both refer to the same
 * SID */

krb5_error_code
samba_kdc_check_pkinit_ms_upn_match(krb5_context context,
				    struct samba_kdc_db_context *kdc_db_ctx,
				    struct samba_kdc_entry *skdc_entry,
				     krb5_const_principal certificate_principal)
{
	krb5_error_code ret;
	struct ldb_dn *realm_dn;
	struct ldb_message *msg;
	struct dom_sid *orig_sid;
	struct dom_sid *target_sid;
	const char *ms_upn_check_attrs[] = {
		"objectSid", NULL
	};

	TALLOC_CTX *mem_ctx = talloc_named(kdc_db_ctx, 0, "samba_kdc_check_pkinit_ms_upn_match");

	if (!mem_ctx) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "samba_kdc_fetch: talloc_named() failed!");
		return ret;
	}

	ret = samba_kdc_lookup_client(context, kdc_db_ctx,
				      mem_ctx, certificate_principal,
				      ms_upn_check_attrs, &realm_dn, &msg);

	if (ret != 0) {
		talloc_free(mem_ctx);
		return ret;
	}

	orig_sid = samdb_result_dom_sid(mem_ctx, skdc_entry->msg, "objectSid");
	target_sid = samdb_result_dom_sid(mem_ctx, msg, "objectSid");

	/* Consider these to be the same principal, even if by a different
	 * name.  The easy and safe way to prove this is by SID
	 * comparison */
	if (!(orig_sid && target_sid && dom_sid_equal(orig_sid, target_sid))) {
		talloc_free(mem_ctx);
#if defined(KRB5KDC_ERR_CLIENT_NAME_MISMATCH) /* MIT */
		return KRB5KDC_ERR_CLIENT_NAME_MISMATCH;
#else /* Heimdal (where this is an enum) */
		return KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
#endif
	}

	talloc_free(mem_ctx);
	return ret;
}

/*
 * Check if a given entry may delegate to this target principal
 * with S4U2Proxy.
 */
krb5_error_code
samba_kdc_check_s4u2proxy(krb5_context context,
			  struct samba_kdc_db_context *kdc_db_ctx,
			  struct samba_kdc_entry *skdc_entry,
			  krb5_const_principal target_principal)
{
	krb5_error_code ret;
	char *tmp = NULL;
	const char *client_dn = NULL;
	const char *target_principal_name = NULL;
	struct ldb_message_element *el;
	struct ldb_val val;
	unsigned int i;
	bool found = false;

	TALLOC_CTX *mem_ctx = talloc_named(kdc_db_ctx, 0, "samba_kdc_check_s4u2proxy");

	if (!mem_ctx) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret,
				       "samba_kdc_check_s4u2proxy:"
				       " talloc_named() failed!");
		return ret;
	}

	client_dn = ldb_dn_get_linearized(skdc_entry->msg->dn);
	if (!client_dn) {
		if (errno == 0) {
			errno = ENOMEM;
		}
		ret = errno;
		krb5_set_error_message(context, ret,
				       "samba_kdc_check_s4u2proxy:"
				       " ldb_dn_get_linearized() failed!");
		return ret;
	}

	/*
	 * The main heimdal code already checked that the target_principal
	 * belongs to the same realm as the client.
	 *
	 * So we just need the principal without the realm,
	 * as that is what is configured in the "msDS-AllowedToDelegateTo"
	 * attribute.
	 */
	ret = krb5_unparse_name_flags(context, target_principal,
				      KRB5_PRINCIPAL_UNPARSE_NO_REALM, &tmp);
	if (ret) {
		talloc_free(mem_ctx);
		krb5_set_error_message(context, ret,
				       "samba_kdc_check_s4u2proxy:"
				       " krb5_unparse_name() failed!");
		return ret;
	}
	DEBUG(10,("samba_kdc_check_s4u2proxy: client[%s] for target[%s]\n",
		 client_dn, tmp));

	target_principal_name = talloc_strdup(mem_ctx, tmp);
	SAFE_FREE(tmp);
	if (target_principal_name == NULL) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret,
				       "samba_kdc_check_s4u2proxy:"
				       " talloc_strdup() failed!");
		return ret;
	}

	el = ldb_msg_find_element(skdc_entry->msg, "msDS-AllowedToDelegateTo");
	if (el == NULL) {
		goto bad_option;
	}

	val = data_blob_string_const(target_principal_name);

	for (i=0; i<el->num_values; i++) {
		struct ldb_val *val1 = &val;
		struct ldb_val *val2 = &el->values[i];
		int cmp;

		if (val1->length != val2->length) {
			continue;
		}

		cmp = strncasecmp((const char *)val1->data,
				  (const char *)val2->data,
				  val1->length);
		if (cmp != 0) {
			continue;
		}

		found = true;
		break;
	}

	if (!found) {
		goto bad_option;
	}

	DEBUG(10,("samba_kdc_check_s4u2proxy: client[%s] allowed target[%s]\n",
		 client_dn, tmp));
	talloc_free(mem_ctx);
	return 0;

bad_option:
	krb5_set_error_message(context, ret,
			       "samba_kdc_check_s4u2proxy: client[%s] "
			       "not allowed for delegation to target[%s]",
			       client_dn,
			       target_principal_name);
	talloc_free(mem_ctx);
	return KRB5KDC_ERR_BADOPTION;
}

NTSTATUS samba_kdc_setup_db_ctx(TALLOC_CTX *mem_ctx, struct samba_kdc_base_context *base_ctx,
				struct samba_kdc_db_context **kdc_db_ctx_out)
{
	int ldb_ret;
	struct ldb_message *msg;
	struct auth_session_info *session_info;
	struct samba_kdc_db_context *kdc_db_ctx;
	/* The idea here is very simple.  Using Kerberos to
	 * authenticate the KDC to the LDAP server is higly likely to
	 * be circular.
	 *
	 * In future we may set this up to use EXERNAL and SSL
	 * certificates, for now it will almost certainly be NTLMSSP_SET_USERNAME
	*/

	kdc_db_ctx = talloc_zero(mem_ctx, struct samba_kdc_db_context);
	if (kdc_db_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	kdc_db_ctx->ev_ctx = base_ctx->ev_ctx;
	kdc_db_ctx->lp_ctx = base_ctx->lp_ctx;
	kdc_db_ctx->msg_ctx = base_ctx->msg_ctx;

	/* get default kdc policy */
	lpcfg_default_kdc_policy(mem_ctx,
				 base_ctx->lp_ctx,
				 &kdc_db_ctx->policy.svc_tkt_lifetime,
				 &kdc_db_ctx->policy.usr_tkt_lifetime,
				 &kdc_db_ctx->policy.renewal_lifetime);

	session_info = system_session(kdc_db_ctx->lp_ctx);
	if (session_info == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* Setup the link to LDB */
	kdc_db_ctx->samdb = samdb_connect(kdc_db_ctx,
					  base_ctx->ev_ctx,
					  base_ctx->lp_ctx,
					  session_info,
					  NULL,
					  0);
	if (kdc_db_ctx->samdb == NULL) {
		DEBUG(1, ("samba_kdc_setup_db_ctx: Cannot open samdb for KDC backend!"));
		talloc_free(kdc_db_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	/* Find out our own krbtgt kvno */
	ldb_ret = samdb_rodc(kdc_db_ctx->samdb, &kdc_db_ctx->rodc);
	if (ldb_ret != LDB_SUCCESS) {
		DEBUG(1, ("samba_kdc_setup_db_ctx: Cannot determine if we are an RODC in KDC backend: %s\n",
			  ldb_errstring(kdc_db_ctx->samdb)));
		talloc_free(kdc_db_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}
	if (kdc_db_ctx->rodc) {
		int my_krbtgt_number;
		const char *secondary_keytab[] = { "msDS-SecondaryKrbTgtNumber", NULL };
		struct ldb_dn *account_dn;
		struct ldb_dn *server_dn = samdb_server_dn(kdc_db_ctx->samdb, kdc_db_ctx);
		if (!server_dn) {
			DEBUG(1, ("samba_kdc_setup_db_ctx: Cannot determine server DN in KDC backend: %s\n",
				  ldb_errstring(kdc_db_ctx->samdb)));
			talloc_free(kdc_db_ctx);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}

		ldb_ret = samdb_reference_dn(kdc_db_ctx->samdb, kdc_db_ctx, server_dn,
					     "serverReference", &account_dn);
		if (ldb_ret != LDB_SUCCESS) {
			DEBUG(1, ("samba_kdc_setup_db_ctx: Cannot determine server account in KDC backend: %s\n",
				  ldb_errstring(kdc_db_ctx->samdb)));
			talloc_free(kdc_db_ctx);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}

		ldb_ret = samdb_reference_dn(kdc_db_ctx->samdb, kdc_db_ctx, account_dn,
					     "msDS-KrbTgtLink", &kdc_db_ctx->krbtgt_dn);
		talloc_free(account_dn);
		if (ldb_ret != LDB_SUCCESS) {
			DEBUG(1, ("samba_kdc_setup_db_ctx: Cannot determine RODC krbtgt account in KDC backend: %s\n",
				  ldb_errstring(kdc_db_ctx->samdb)));
			talloc_free(kdc_db_ctx);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}

		ldb_ret = dsdb_search_one(kdc_db_ctx->samdb, kdc_db_ctx,
					  &msg, kdc_db_ctx->krbtgt_dn, LDB_SCOPE_BASE,
					  secondary_keytab,
					  DSDB_SEARCH_NO_GLOBAL_CATALOG,
					  "(&(objectClass=user)(msDS-SecondaryKrbTgtNumber=*))");
		if (ldb_ret != LDB_SUCCESS) {
			DEBUG(1, ("samba_kdc_setup_db_ctx: Cannot read krbtgt account %s in KDC backend to get msDS-SecondaryKrbTgtNumber: %s: %s\n",
				  ldb_dn_get_linearized(kdc_db_ctx->krbtgt_dn),
				  ldb_errstring(kdc_db_ctx->samdb),
				  ldb_strerror(ldb_ret)));
			talloc_free(kdc_db_ctx);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
		my_krbtgt_number = ldb_msg_find_attr_as_int(msg, "msDS-SecondaryKrbTgtNumber", -1);
		if (my_krbtgt_number == -1) {
			DEBUG(1, ("samba_kdc_setup_db_ctx: Cannot read msDS-SecondaryKrbTgtNumber from krbtgt account %s in KDC backend: got %d\n",
				  ldb_dn_get_linearized(kdc_db_ctx->krbtgt_dn),
				  my_krbtgt_number));
			talloc_free(kdc_db_ctx);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
		kdc_db_ctx->my_krbtgt_number = my_krbtgt_number;

	} else {
		kdc_db_ctx->my_krbtgt_number = 0;
		ldb_ret = dsdb_search_one(kdc_db_ctx->samdb, kdc_db_ctx,
					  &msg,
					  ldb_get_default_basedn(kdc_db_ctx->samdb),
					  LDB_SCOPE_SUBTREE,
					  krbtgt_attrs,
					  DSDB_SEARCH_NO_GLOBAL_CATALOG,
					  "(&(objectClass=user)(samAccountName=krbtgt))");

		if (ldb_ret != LDB_SUCCESS) {
			DEBUG(1, ("samba_kdc_fetch: could not find own KRBTGT in DB: %s\n", ldb_errstring(kdc_db_ctx->samdb)));
			talloc_free(kdc_db_ctx);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
		kdc_db_ctx->krbtgt_dn = talloc_steal(kdc_db_ctx, msg->dn);
		kdc_db_ctx->my_krbtgt_number = 0;
		talloc_free(msg);
	}
	*kdc_db_ctx_out = kdc_db_ctx;
	return NT_STATUS_OK;
}
