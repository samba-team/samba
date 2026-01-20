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
#include "librpc/gen_ndr/ndr_security.h"
#include "auth/auth.h"
#include "auth/auth_sam.h"
#include "dsdb/gmsa/util.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/proto.h"
#include "dsdb/common/util.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"
#include "param/secrets.h"
#include "lib/crypto/gkdi.h"
#include "../lib/crypto/md4.h"
#include "lib/util/memory.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "kdc/authn_policy_util.h"
#include "kdc/sdb.h"
#include "kdc/samba_kdc.h"
#include "kdc/db-glue.h"
#include "kdc/pac-glue.h"
#include "librpc/gen_ndr/ndr_irpc_c.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_keycredlink.h"
#include "talloc.h"
#include "util/data_blob.h"
#include "util/debug.h"
#include "util/samba_util.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_KERBEROS

#undef strcasecmp
#undef strncasecmp

#define SAMBA_KVNO_GET_KRBTGT(kvno) \
	((uint16_t)(((uint32_t)kvno) >> 16))

#define SAMBA_KVNO_GET_VALUE(kvno) \
	((uint16_t)(((uint32_t)kvno) & 0xFFFF))

#define SAMBA_KVNO_AND_KRBTGT(kvno, krbtgt) \
	((krb5_kvno)((((uint32_t)kvno) & 0xFFFF) | \
	 ((((uint32_t)krbtgt) << 16) & 0xFFFF0000)))

enum trust_direction {
	UNKNOWN = 0,
	INBOUND = LSA_TRUST_DIRECTION_INBOUND,
	OUTBOUND = LSA_TRUST_DIRECTION_OUTBOUND
};

static const char * const trust_attrs[] = {
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
	"msDS-IngressClaimsTransformationPolicy",
	"msDS-EgressClaimsTransformationPolicy",
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
                DBG_WARNING("Unable to get binding handle for dreplsrv\n");
                TALLOC_FREE(tmp_ctx);
                return;
        }

        r.in.user_dn = ldb_dn_get_linearized(user_dn);
        if (r.in.user_dn == NULL) {
                DBG_WARNING("Unable to get user DN\n");
                TALLOC_FREE(tmp_ctx);
                return;
        }

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
    const struct ldb_val *gentime = NULL;
    time_t t;
    int ret;

    gentime = ldb_msg_find_ldb_val(msg, attr);
    ret = ldb_val_to_time(gentime, &t);
    if (ret) {
	    return default_val;
    }

    return t;
}

static struct SDBFlags uf2SDBFlags(krb5_context context, uint32_t userAccountControl, enum samba_kdc_ent_type ent_type)
{
	struct SDBFlags flags = {};

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
	if (userAccountControl & UF_PASSWD_NOTREQD) {
		flags.invalid = 1;
	}
*/
/*
	UF_PASSWD_CANT_CHANGE and UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED are irrelevant
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

	if (userAccountControl & UF_NO_AUTH_DATA_REQUIRED) {
		flags.no_auth_data_reqd = 1;
	}

	return flags;
}

static int samba_kdc_entry_destructor(struct samba_kdc_entry *p)
{
	if (p->db_entry != NULL) {
		/*
		 * A sdb_entry still has a reference
		 */
		return -1;
	}

	if (p->kdc_entry != NULL) {
		/*
		 * hdb_entry or krb5_db_entry still
		 * have a reference...
		 */
		return -1;
	}

	return 0;
}

/*
 * Sort keys in descending order of strength.
 *
 * Explanation from Greg Hudson:
 *
 * To encrypt tickets only the first returned key is used by the MIT KDC.  The
 * other keys just communicate support for session key enctypes, and aren't
 * really used.  The encryption key for the ticket enc part doesn't have
 * to be of a type requested by the client. The session key enctype is chosen
 * based on the client preference order, limited by the set of enctypes present
 * in the server keys (unless the string attribute is set on the server
 * principal overriding that set).
 */

static int sdb_key_strength_priority(krb5_enctype etype)
{
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
	int i;

	for (i = 0; i < ARRAY_SIZE(etype_list); i++) {
		if (etype == etype_list[i]) {
			break;
		}
	}

	return ARRAY_SIZE(etype_list) - i;
}

static int sdb_key_strength_cmp(const struct sdb_key *k1, const struct sdb_key *k2)
{
	int p1 = sdb_key_strength_priority(KRB5_KEY_TYPE(&k1->key));
	int p2 = sdb_key_strength_priority(KRB5_KEY_TYPE(&k2->key));

	if (p1 == p2) {
		return 0;
	}

	if (p1 > p2) {
		/*
		 * Higher priority comes first
		 */
		return -1;
	} else {
		return 1;
	}
}

static void samba_kdc_sort_keys(struct sdb_keys *keys)
{
	if (keys == NULL) {
		return;
	}

	TYPESAFE_QSORT(keys->val, keys->len, sdb_key_strength_cmp);
}

int samba_kdc_set_fixed_keys(krb5_context context,
			     const struct ldb_val *secretbuffer,
			     uint32_t supported_enctypes,
			     struct sdb_keys *keys)
{
	uint16_t allocated_keys = 0;
	int ret;

	allocated_keys = 3;
	keys->len = 0;
	keys->val = calloc(allocated_keys, sizeof(struct sdb_key));
	if (keys->val == NULL) {
		memset(secretbuffer->data, 0, secretbuffer->length);
		ret = ENOMEM;
		goto out;
	}

	if (supported_enctypes & ENC_HMAC_SHA1_96_AES256) {
		struct sdb_key key = {};

		ret = smb_krb5_keyblock_init_contents(context,
						      ENCTYPE_AES256_CTS_HMAC_SHA1_96,
						      secretbuffer->data,
						      MIN(secretbuffer->length, 32),
						      &key.key);
		if (ret) {
			memset(secretbuffer->data, 0, secretbuffer->length);
			goto out;
		}

		keys->val[keys->len] = key;
		keys->len++;
	}

	if (supported_enctypes & ENC_HMAC_SHA1_96_AES128) {
		struct sdb_key key = {};

		ret = smb_krb5_keyblock_init_contents(context,
						      ENCTYPE_AES128_CTS_HMAC_SHA1_96,
						      secretbuffer->data,
						      MIN(secretbuffer->length, 16),
						      &key.key);
		if (ret) {
			memset(secretbuffer->data, 0, secretbuffer->length);
			goto out;
		}

		keys->val[keys->len] = key;
		keys->len++;
	}

	if (supported_enctypes & ENC_RC4_HMAC_MD5) {
		struct sdb_key key = {};

		ret = smb_krb5_keyblock_init_contents(context,
						      ENCTYPE_ARCFOUR_HMAC,
						      secretbuffer->data,
						      MIN(secretbuffer->length, 16),
						      &key.key);
		if (ret) {
			memset(secretbuffer->data, 0, secretbuffer->length);
			goto out;
		}

		keys->val[keys->len] = key;
		keys->len++;
	}
	ret = 0;
out:
	return ret;
}


static int samba_kdc_set_random_keys(krb5_context context,
				     uint32_t supported_enctypes,
				     struct sdb_keys *keys)
{
	struct ldb_val secret_val;
	uint8_t secretbuffer[32];

	/*
	 * Fake keys until we have a better way to reject
	 * non-pkinit requests.
	 *
	 * We just need to indicate which encryption types are
	 * supported.
	 */
	generate_secret_buffer(secretbuffer, sizeof(secretbuffer));

	secret_val = data_blob_const(secretbuffer,
				     sizeof(secretbuffer));
	return samba_kdc_set_fixed_keys(context,
					&secret_val,
					supported_enctypes,
					keys);
}

struct samba_kdc_user_keys {
	struct sdb_keys *skeys;
	uint32_t kvno;
	uint32_t *returned_kvno;
	uint32_t supported_enctypes;
	uint32_t *available_enctypes;
	const struct samr_Password *nthash;
	const char *salt_string;
	uint16_t num_pkeys;
	const struct package_PrimaryKerberosKey4 *pkeys;
};

static krb5_error_code samba_kdc_fill_user_keys(krb5_context context,
						struct samba_kdc_user_keys *p)
{
	/*
	 * Make sure we'll never reveal DES keys
	 */
	uint32_t supported_enctypes = p->supported_enctypes &= ~(ENC_CRC32 | ENC_RSA_MD5);
	uint32_t _available_enctypes = 0;
	uint32_t *available_enctypes = p->available_enctypes;
	uint32_t _returned_kvno = 0;
	uint32_t *returned_kvno = p->returned_kvno;
	uint32_t num_pkeys = p->num_pkeys;
	uint32_t allocated_keys = num_pkeys;
	uint32_t i;
	int ret;

	if (available_enctypes == NULL) {
		available_enctypes = &_available_enctypes;
	}

	*available_enctypes = 0;

	if (returned_kvno == NULL) {
		returned_kvno = &_returned_kvno;
	}

	*returned_kvno = p->kvno;

	if (p->nthash != NULL) {
		allocated_keys += 1;
	}

	allocated_keys = MAX(1, allocated_keys);

	/* allocate space to decode into */
	p->skeys->len = 0;
	p->skeys->val = calloc(allocated_keys, sizeof(struct sdb_key));
	if (p->skeys->val == NULL) {
		return ENOMEM;
	}

	for (i=0; i < num_pkeys; i++) {
		struct sdb_key key = {};
		uint32_t enctype_bit;

		if (p->pkeys[i].value == NULL) {
			continue;
		}

		enctype_bit = kerberos_enctype_to_bitmap(p->pkeys[i].keytype);
		if (!(enctype_bit & supported_enctypes)) {
			continue;
		}

		if (p->salt_string != NULL) {
			DATA_BLOB salt;

			salt = data_blob_string_const(p->salt_string);

			key.salt = calloc(1, sizeof(*key.salt));
			if (key.salt == NULL) {
				ret = ENOMEM;
				goto fail;
			}

			key.salt->type = KRB5_PW_SALT;

			ret = smb_krb5_copy_data_contents(&key.salt->salt,
							  salt.data,
							  salt.length);
			if (ret) {
				*key.salt = (struct sdb_salt) {};
				sdb_key_free(&key);
				goto fail;
			}
		}

		ret = smb_krb5_keyblock_init_contents(context,
						      p->pkeys[i].keytype,
						      p->pkeys[i].value->data,
						      p->pkeys[i].value->length,
						      &key.key);
		if (ret == 0) {
			p->skeys->val[p->skeys->len++] = key;
			*available_enctypes |= enctype_bit;
			continue;
		}
		ZERO_STRUCT(key.key);
		sdb_key_free(&key);
		if (ret == KRB5_PROG_ETYPE_NOSUPP) {
			DEBUG(2,("Unsupported keytype ignored - type %u\n",
				 p->pkeys[i].keytype));
			ret = 0;
			continue;
		}

		goto fail;
	}

	if (p->nthash != NULL && (supported_enctypes & ENC_RC4_HMAC_MD5)) {
		struct sdb_key key = {};

		ret = smb_krb5_keyblock_init_contents(context,
						      ENCTYPE_ARCFOUR_HMAC,
						      p->nthash->hash,
						      sizeof(p->nthash->hash),
						      &key.key);
		if (ret == 0) {
			p->skeys->val[p->skeys->len++] = key;

			*available_enctypes |= ENC_RC4_HMAC_MD5;
		} else if (ret == KRB5_PROG_ETYPE_NOSUPP) {
			DEBUG(2,("Unsupported keytype ignored - type %u\n",
				 ENCTYPE_ARCFOUR_HMAC));
			ret = 0;
		}
		if (ret != 0) {
			goto fail;
		}
	}

	samba_kdc_sort_keys(p->skeys);

	return 0;
fail:
	sdb_keys_free(p->skeys);
	return ret;
}

static krb5_error_code samba_kdc_merge_keys(struct sdb_keys *keys,
					    struct sdb_keys *old_keys)
{
	unsigned num_keys;
	unsigned num_old_keys;
	unsigned total_keys;
	unsigned j;
	struct sdb_key *skeys = NULL;

	if (keys == NULL || old_keys == NULL) {
		return EINVAL;
	}

	num_keys = keys->len;
	num_old_keys = old_keys->len;
	total_keys = num_keys + num_old_keys;

	skeys = realloc_p(keys->val, struct sdb_key, total_keys);
	if (skeys == NULL) {
		return ENOMEM;
	}
	keys->val = skeys;

	for (j = 0; j < num_old_keys; ++j) {
		keys->val[num_keys + j] = old_keys->val[j];
	}
	keys->len = total_keys;

	old_keys->len = 0;
	SAFE_FREE(old_keys->val);

	return 0;
}

krb5_error_code samba_kdc_message2entry_keys(krb5_context context,
					     TALLOC_CTX *mem_ctx,
					     struct ldb_context *ldb,
					     const struct ldb_message *msg,
					     bool is_krbtgt,
					     bool is_rodc,
					     uint32_t userAccountControl,
					     enum samba_kdc_ent_type ent_type,
					     unsigned flags,
					     krb5_kvno requested_kvno,
					     struct sdb_entry *entry,
					     const uint32_t supported_enctypes_in,
					     uint32_t *supported_enctypes_out)
{
	krb5_error_code ret = 0;
	enum ndr_err_code ndr_err;
	struct samr_Password *hash;
	unsigned int num_ntPwdHistory = 0;
	struct samr_Password *ntPwdHistory = NULL;
	struct samr_Password *old_hash = NULL;
	struct samr_Password *older_hash = NULL;
	const struct ldb_val *sc_val;
	struct supplementalCredentialsBlob scb;
	struct supplementalCredentialsPackage *scpk = NULL;
	struct package_PrimaryKerberosBlob _pkb;
	struct package_PrimaryKerberosCtr4 *pkb4 = NULL;
	int krbtgt_number = 0;
	uint32_t current_kvno;
	uint32_t old_kvno = 0;
	uint32_t older_kvno = 0;
	uint32_t returned_kvno = 0;
	uint16_t i;
	struct samba_kdc_user_keys keys = { .num_pkeys = 0, };
	struct samba_kdc_user_keys old_keys = { .num_pkeys = 0, };
	struct samba_kdc_user_keys older_keys = { .num_pkeys = 0, };
	uint32_t available_enctypes = 0;
	uint32_t supported_enctypes = supported_enctypes_in;
	const bool exporting_keytab = flags & SDB_F_ADMIN_DATA;

	*supported_enctypes_out = 0;

	if (entry == NULL) {
		DBG_ERR("entry is NULL");
		return EINVAL;
	}

	/* Is this the krbtgt or a RODC krbtgt */
	if (is_rodc) {
		krbtgt_number = ldb_msg_find_attr_as_int(msg, "msDS-SecondaryKrbTgtNumber", -1);

		if (krbtgt_number == -1) {
			return EINVAL;
		}
		if (krbtgt_number == 0) {
			return EINVAL;
		}
	}

	if (flags & SDB_F_USER2USER_PRINCIPAL) {
		/*
		 * User2User uses the session key
		 * from the additional ticket,
		 * so we just provide random keys
		 * here in order to make sure
		 * we never expose the user password
		 * keys.
		 */
		ret = samba_kdc_set_random_keys(context,
						supported_enctypes,
						&entry->keys);

		*supported_enctypes_out = supported_enctypes & ENC_ALL_TYPES;

		goto out;
	}

	if ((ent_type == SAMBA_KDC_ENT_TYPE_CLIENT)
	    && (userAccountControl & UF_SMARTCARD_REQUIRED)) {
		ret = samba_kdc_set_random_keys(context,
						supported_enctypes,
						&entry->keys);

		*supported_enctypes_out = supported_enctypes & ENC_ALL_TYPES;

		goto out;
	}

	current_kvno = ldb_msg_find_attr_as_int(msg, "msDS-KeyVersionNumber", 0);
	if (current_kvno > 1) {
		old_kvno = current_kvno - 1;
	}
	if (current_kvno > 2) {
		older_kvno = current_kvno - 2;
	}
	if (is_krbtgt) {
		/*
		 * Even for the main krbtgt account
		 * we have to strictly split the kvno into
		 * two 16-bit parts and the upper 16-bit
		 * need to be all zero, even if
		 * the msDS-KeyVersionNumber has a value
		 * larger than 65535.
		 *
		 * See https://bugzilla.samba.org/show_bug.cgi?id=14951
		 */
		current_kvno = SAMBA_KVNO_GET_VALUE(current_kvno);
		old_kvno = SAMBA_KVNO_GET_VALUE(old_kvno);
		older_kvno = SAMBA_KVNO_GET_VALUE(older_kvno);
		requested_kvno = SAMBA_KVNO_GET_VALUE(requested_kvno);
	}

	/* Get keys from the db */

	hash = samdb_result_hash(mem_ctx, msg, "unicodePwd");
	num_ntPwdHistory = samdb_result_hashes(mem_ctx, msg,
					       "ntPwdHistory",
					       &ntPwdHistory);
	if (num_ntPwdHistory > 1) {
		old_hash = &ntPwdHistory[1];
	}
	if (num_ntPwdHistory > 2) {
		older_hash = &ntPwdHistory[2];
	}
	sc_val = ldb_msg_find_ldb_val(msg, "supplementalCredentials");

	/* supplementalCredentials if present */
	if (sc_val) {
		ndr_err = ndr_pull_struct_blob_all(sc_val, mem_ctx, &scb,
						   (ndr_pull_flags_fn_t)ndr_pull_supplementalCredentialsBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
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
			if (scb.sub.packages[i].name != NULL &&
			    strcmp("Primary:Kerberos-Newer-Keys", scb.sub.packages[i].name) == 0)
			{
				scpk = &scb.sub.packages[i];
				if (!scpk->data || !scpk->data[0]) {
					scpk = NULL;
					continue;
				}
				break;
			}
		}
	}
	/*
	 * Primary:Kerberos-Newer-Keys element
	 * of supplementalCredentials
	 *
	 * The legacy Primary:Kerberos only contains
	 * single DES keys, which are completely ignored
	 * now.
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

		if (_pkb.version != 4) {
			ret = EINVAL;
			krb5_set_error_message(context, ret, "samba_kdc_message2entry_keys: Primary:Kerberos-Newer-Keys not version 4");
			krb5_warnx(context, "samba_kdc_message2entry_keys: Primary:Kerberos-Newer-Keys not version 4");
			goto out;
		}

		pkb4 = &_pkb.ctr.ctr4;
	}

	keys = (struct samba_kdc_user_keys) {
		.kvno = current_kvno,
		.supported_enctypes = supported_enctypes,
		.nthash = hash,
		.salt_string = pkb4 != NULL ? pkb4->salt.string : NULL,
		.num_pkeys = pkb4 != NULL ? pkb4->num_keys : 0,
		.pkeys = pkb4 != NULL ? pkb4->keys : NULL,
	};

	old_keys = (struct samba_kdc_user_keys) {
		.kvno = old_kvno,
		.supported_enctypes = supported_enctypes,
		.nthash = old_hash,
		.salt_string = pkb4 != NULL ? pkb4->salt.string : NULL,
		.num_pkeys = pkb4 != NULL ? pkb4->num_old_keys : 0,
		.pkeys = pkb4 != NULL ? pkb4->old_keys : NULL,
	};
	older_keys = (struct samba_kdc_user_keys) {
		.kvno = older_kvno,
		.supported_enctypes = supported_enctypes,
		.nthash = older_hash,
		.salt_string = pkb4 != NULL ? pkb4->salt.string : NULL,
		.num_pkeys = pkb4 != NULL ? pkb4->num_older_keys : 0,
		.pkeys = pkb4 != NULL ? pkb4->older_keys : NULL,
	};

	if (flags & SDB_F_KVNO_SPECIFIED) {
		if (requested_kvno == keys.kvno) {
			/*
			 * The current kvno was requested,
			 * so we return it.
			 */
			keys.skeys = &entry->keys;
			keys.available_enctypes = &available_enctypes;
			keys.returned_kvno = &returned_kvno;
		} else if (requested_kvno == 0) {
			/*
			 * don't return any keys
			 */
		} else if (requested_kvno == old_keys.kvno) {
			/*
			 * return the old keys as default keys
			 * with the requested kvno.
			 */
			old_keys.skeys = &entry->keys;
			old_keys.available_enctypes = &available_enctypes;
			old_keys.returned_kvno = &returned_kvno;
		} else if (requested_kvno == older_keys.kvno) {
			/*
			 * return the older keys as default keys
			 * with the requested kvno.
			 */
			older_keys.skeys = &entry->keys;
			older_keys.available_enctypes = &available_enctypes;
			older_keys.returned_kvno = &returned_kvno;
		} else {
			/*
			 * don't return any keys
			 */
		}
	} else {
		bool include_history = false;

		if ((flags & SDB_F_GET_CLIENT) && (flags & SDB_F_FOR_AS_REQ)) {
			include_history = true;
		} else if (exporting_keytab) {
			include_history = true;
		}

		keys.skeys = &entry->keys;
		keys.available_enctypes = &available_enctypes;
		keys.returned_kvno = &returned_kvno;

		if (include_history && old_keys.kvno != 0) {
			old_keys.skeys = &entry->old_keys;
		}
		if (include_history && older_keys.kvno != 0) {
			older_keys.skeys = &entry->older_keys;
		}
	}

	if (keys.skeys != NULL) {
		ret = samba_kdc_fill_user_keys(context, &keys);
		if (ret != 0) {
			goto out;
		}
	}

	if (old_keys.skeys != NULL) {
		ret = samba_kdc_fill_user_keys(context, &old_keys);
		if (ret != 0) {
			goto out;
		}

		if (keys.skeys != NULL && !exporting_keytab) {
			bool is_gmsa;

			is_gmsa = dsdb_account_is_gmsa(ldb, msg);
			if (is_gmsa) {
				NTTIME current_time;
				bool gmsa_key_is_recent;
				bool ok;

				ok = dsdb_gmsa_current_time(ldb, &current_time);
				if (!ok) {
					ret = EINVAL;
					goto out;
				}

				gmsa_key_is_recent = samdb_gmsa_key_is_recent(
					msg, current_time);
				if (gmsa_key_is_recent) {
					/*
					 * As the current gMSA keys are less
					 * than five minutes old, the previous
					 * set of keys remains valid. The
					 * Heimdal KDC will try each of the
					 * current keys when decrypting a
					 * client’s PA‐DATA, so by merging the
					 * old set into the current set we can
					 * cause both sets to be considered for
					 * decryption.
					 */
					ret = samba_kdc_merge_keys(
						keys.skeys, old_keys.skeys);
					if (ret) {
						goto out;
					}
				}
			}
		}
	}

	if (older_keys.skeys != NULL) {
		ret = samba_kdc_fill_user_keys(context, &older_keys);
		if (ret != 0) {
			goto out;
		}
	}

	*supported_enctypes_out |= available_enctypes;

	if (is_krbtgt) {
		/*
		 * Even for the main krbtgt account
		 * we have to strictly split the kvno into
		 * two 16-bit parts and the upper 16-bit
		 * need to be all zero, even if
		 * the msDS-KeyVersionNumber has a value
		 * larger than 65535.
		 *
		 * See https://bugzilla.samba.org/show_bug.cgi?id=14951
		 */
		returned_kvno = SAMBA_KVNO_AND_KRBTGT(returned_kvno, krbtgt_number);
	}
	entry->kvno = returned_kvno;

out:
	return ret;
}

static krb5_error_code is_principal_component_equal_impl(krb5_context context,
							 krb5_const_principal principal,
							 unsigned int component,
							 const char *string,
							 bool do_strcasecmp,
							 bool *eq)
{
	const char *p;

#if defined(HAVE_KRB5_PRINCIPAL_GET_COMP_STRING)
	if (component >= krb5_princ_size(context, principal)) {
		/* A non‐existent component compares equal to no string. */
		*eq = false;
		return 0;
	}
	p = krb5_principal_get_comp_string(context, principal, component);
	if (p == NULL) {
		return ENOENT;
	}
	if (do_strcasecmp) {
		*eq = strcasecmp(p, string) == 0;
	} else {
		*eq = strcmp(p, string) == 0;
	}
	return 0;
#else
	size_t len;
	krb5_data d;
	krb5_error_code ret = 0;

	if (component > INT_MAX) {
		return EINVAL;
	}

	if (component >= krb5_princ_size(context, principal)) {
		/* A non‐existent component compares equal to no string. */
		*eq = false;
		return 0;
	}

	ret = smb_krb5_princ_component(context, principal, component, &d);
	if (ret) {
		return ret;
	}

	p = d.data;

	len = strlen(string);
	if (d.length != len) {
		*eq = false;
		return 0;
	}

	if (do_strcasecmp) {
		*eq = strncasecmp(p, string, len) == 0;
	} else {
		*eq = memcmp(p, string, len) == 0;
	}
	return 0;
#endif
}

static krb5_error_code is_principal_component_equal_ignoring_case(krb5_context context,
								  krb5_const_principal principal,
								  unsigned int component,
								  const char *string,
								  bool *eq)
{
	return is_principal_component_equal_impl(context,
						 principal,
						 component,
						 string,
						 true /* do_strcasecmp */,
						 eq);
}

static krb5_error_code is_principal_component_equal(krb5_context context,
						    krb5_const_principal principal,
						    unsigned int component,
						    const char *string,
						    bool *eq)
{
	return is_principal_component_equal_impl(context,
						 principal,
						 component,
						 string,
						 false /* do_strcasecmp */,
						 eq);
}

static krb5_error_code is_kadmin_changepw(krb5_context context,
					  krb5_const_principal principal,
					  bool *is_changepw)
{
	krb5_error_code ret = 0;
	bool eq = false;

	if (krb5_princ_size(context, principal) != 2) {
		*is_changepw = false;
		return 0;
	}

	ret = is_principal_component_equal(context, principal, 0, "kadmin", &eq);
	if (ret) {
		return ret;
	}

	if (!eq) {
		*is_changepw = false;
		return 0;
	}

	ret = is_principal_component_equal(context, principal, 1, "changepw", &eq);
	if (ret) {
		return ret;
	}

	*is_changepw = eq;
	return 0;
}

static krb5_error_code samba_kdc_get_entry_principal(
		krb5_context context,
		struct samba_kdc_db_context *kdc_db_ctx,
		const char *samAccountName,
		enum samba_kdc_ent_type ent_type,
		unsigned flags,
		bool is_kadmin_changepw,
		krb5_const_principal in_princ,
		krb5_principal *out_princ)
{
	struct loadparm_context *lp_ctx = kdc_db_ctx->lp_ctx;
	krb5_error_code code = 0;
	bool canon = flags & (SDB_F_CANON|SDB_F_FORCE_CANON);

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

	/*
	 * We need to ensure that the kadmin/changepw principal isn't able to
	 * issue krbtgt tickets, even if canonicalization is turned on.
	 */
	if (!is_kadmin_changepw) {
		if (ent_type == SAMBA_KDC_ENT_TYPE_KRBTGT && canon) {
			/*
			 * When requested to do so, ensure that both
			 * the realm values in the principal are set
			 * to the upper case, canonical realm
			 */
			code = smb_krb5_make_principal(context,
						       out_princ,
						       lpcfg_realm(lp_ctx),
						       "krbtgt",
						       lpcfg_realm(lp_ctx),
						       NULL);
			if (code != 0) {
				return code;
			}
			smb_krb5_principal_set_type(context,
						    *out_princ,
						    KRB5_NT_SRV_INST);

			return 0;
		}

		if ((canon && flags & (SDB_F_FORCE_CANON|SDB_F_FOR_AS_REQ)) ||
		    (ent_type == SAMBA_KDC_ENT_TYPE_ANY && in_princ == NULL)) {
			/*
			 * SDB_F_CANON maps from the canonicalize flag in the
			 * packet, and has a different meaning between AS-REQ
			 * and TGS-REQ.  We only change the principal in the
			 * AS-REQ case.
			 *
			 * The SDB_F_FORCE_CANON is for new MIT KDC code that
			 * wants the canonical name in all lookups, and takes
			 * care to canonicalize only when appropriate.
			 */
			code = smb_krb5_make_principal(context,
						      out_princ,
						      lpcfg_realm(lp_ctx),
						      samAccountName,
						      NULL);
			return code;
		}
	}

	/*
	 * For a krbtgt entry, this appears to be required regardless of the
	 * canonicalize flag from the client.
	 */
	code = krb5_copy_principal(context, in_princ, out_princ);
	if (code != 0) {
		return code;
	}

	/*
	 * While we have copied the client principal, tests show that Win2k3
	 * returns the 'corrected' realm, not the client-specified realm.  This
	 * code attempts to replace the client principal's realm with the one
	 * we determine from our records
	 */
	code = smb_krb5_principal_set_realm(context,
					    *out_princ,
					    lpcfg_realm(lp_ctx));

	return code;
}


/**
 * @brief Copy the contents of a data blob to a krb5_data element
 *
 * @param[in]  blob  The source data blob
 * @param[out] krb5  The target krb5_data element
 *
 * @return 0      No error
 *         ENOMEM memory allocation error
 *
 * @note Memory is allocated with malloc and needs to be freed
 */
static krb5_error_code data_blob_to_krb5_data( DATA_BLOB *blob, krb5_data *krb5)
{
	krb5->data = malloc(blob->length);
	if (krb5->data == NULL) {
		return ENOMEM;
	}
	memcpy(krb5->data, blob->data, blob->length);
	krb5->length = blob->length;
	return 0;
}


/**
 * @brief Copy the contents of a hex string data blob to a binary
 *        krb5_data element
 *
 * @param[in]  blob  The source data blob
 * @param[out] krb5  The target krb5_data element
 *
 * @return 0      No error
 *         ENOMEM memory allocation error
 *         EINVAL data blob is not a valid hex string encoding
 *
 * @note Memory is allocated with malloc and needs to be freed
 */
static krb5_error_code db_hex_str_to_krb5_data(
	DATA_BLOB *blob,
	krb5_data *krb5)
{

	size_t size = 0;

	if( (blob->length%2) != 0) {
		DBG_ERR(
			"Hex string [%*.*s] "
			"does not have an even length",
			(int) blob->length,
			(int) blob->length,
			(char *) blob->data);
		return EINVAL;
	}
	krb5->length = (blob->length/2);
	krb5->data = malloc(krb5->length);
	if (krb5->data == NULL) {
		krb5->length = 0;
		return ENOMEM;
	}
	size = strhex_to_str(krb5->data,
			     krb5->length,
		             (const char *) blob->data,
		             blob->length);
	if (size != krb5->length) {
		krb5->length = 0;
		SAFE_FREE(krb5->data);
		return EINVAL;
	}
	return 0;
}

/*
 * Helper macro to populate the data blob constants used by
 * populate_certificate_mapping and parse_certificate_mapping
 */
#define DATA_BLOB_STRING(str) {\
	.data = discard_const_p(uint8_t, str), \
	.length = sizeof(str) - 1 \
}
static const DATA_BLOB ISSUER_NAME = DATA_BLOB_STRING("I");
static const DATA_BLOB SUBJECT_NAME = DATA_BLOB_STRING("S");
static const DATA_BLOB SERIAL_NUMBER = DATA_BLOB_STRING("SR");
static const DATA_BLOB SUBJECT_KEY_IDENTIFIER = DATA_BLOB_STRING("SKI");
static const DATA_BLOB PUBLIC_KEY = DATA_BLOB_STRING("SHA1-PUKEY");
static const DATA_BLOB RFC822 = DATA_BLOB_STRING("RFC822");
static const DATA_BLOB X509_HEADER = DATA_BLOB_STRING("X509:");
#undef DATA_BLOB_STRING

/**
 * @brief Populate the certificate mapping from the tag and value
 *
 * @param[in]     tag      the tag i.e. I, S, SKI, .....
 * @param[in]     value    the value associated with the tag
 * @param[in,out] mapping  the mapping to be updated
 *
 * @return      0 No error
 *         EINVAL tag or value are invalid
 *         ENOMEM memory allocation error
 *
 * @note Memory is allocated with malloc and needs to be freed with
 *       sdb_certificate_mapping_free
 */
static krb5_error_code populate_certificate_mapping(
	DATA_BLOB *tag,
	DATA_BLOB *value,
	struct sdb_certificate_mapping *mapping)
{
	krb5_error_code ret = 0;

	if (tag->length == 0) {
		DBG_WARNING("altSecurityIdentities empty tag");
		return EINVAL;
	}
	if (value->length == 0) {
		DBG_WARNING("altSecurityIdentities no value for %*.*s",
			    (int) tag->length,
			    (int) tag->length,
			    tag->data);
		return EINVAL;
	}

	if (data_blob_cmp(&ISSUER_NAME, tag) == 0) {
		/* discard any previous value */
		if (mapping->issuer_name.data != NULL) {
			SAFE_FREE(mapping->issuer_name.data);
			mapping->issuer_name.length = 0;
		}
		ret = data_blob_to_krb5_data(value, &mapping->issuer_name);

	} else if (data_blob_cmp(&SUBJECT_NAME, tag) == 0) {
		/* discard any previous value */
		if (mapping->subject_name.data != NULL) {
			SAFE_FREE(mapping->subject_name.data);
			mapping->subject_name.length = 0;
		}
		ret = data_blob_to_krb5_data(value, &mapping->subject_name);

	} else if (data_blob_cmp(&RFC822, tag) == 0) {
		/* discard any previous value */
		if (mapping->rfc822.data != NULL) {
			SAFE_FREE(mapping->rfc822.data);
			mapping->rfc822.length = 0;
		}
		ret = data_blob_to_krb5_data(value, &mapping->rfc822);

	} else if (data_blob_cmp(&SERIAL_NUMBER, tag ) == 0) {
		/* discard any previous value */
		if (mapping->serial_number.data != NULL) {
			SAFE_FREE(mapping->serial_number.data);
			mapping->serial_number.length = 0;
		}
		ret = db_hex_str_to_krb5_data(value, &mapping->serial_number);

	} else if (data_blob_cmp(&SUBJECT_KEY_IDENTIFIER, tag) == 0) {
		/* discard any previous value */
		if (mapping->ski.data != NULL) {
			SAFE_FREE(mapping->ski.data);
			mapping->ski.length = 0;
		}
		ret = db_hex_str_to_krb5_data(value, &mapping->ski);

	} else if (data_blob_cmp(&PUBLIC_KEY, tag) == 0) {
		/* discard any previous value */
		if (mapping->public_key.data != NULL) {
			SAFE_FREE(mapping->public_key.data);
			mapping->public_key.length = 0;
		}
		ret = db_hex_str_to_krb5_data(value, &mapping->public_key);

	} else {
		DBG_WARNING("altSecurityIdentities invalid tag %*.*s",
			    (int) tag->length,
			    (int) tag->length,
			    tag->data);
		ret = EINVAL;
	}
	return ret;
}


/**
 * @brief does the krb5 element have a value?
 *
 * @param[in] krb5  The target krb5_data element
 *
 * @return TRUE  krb5 has a value
 *         FALSE krb5 has no value i.e. it's empty
 */
static krb5_boolean krb5_data_has_value(krb5_data *krb5)
{
	if (krb5->data == NULL || krb5->length == 0) {
		return FALSE;
	}
	return TRUE;
}
/**
 * @brief is the certificate mapping a strong mapping?
 *
 * @param[in] mapping the certificate mapping to examine.
 *
 * @return TRUE  mapping is strong
 *         FALSE mapping is weak
 */
static krb5_boolean is_strong_certificate_mapping(
	struct sdb_certificate_mapping *mapping)
{
	/* Subject Key Identifier */
	if (krb5_data_has_value(&mapping->ski)) {
		return TRUE;
	}
	/* Public Key */
	if (krb5_data_has_value(&mapping->public_key)) {
		return TRUE;
	}
	/* Issuer Serial Number */
	if (krb5_data_has_value(&mapping->issuer_name) &&
	    krb5_data_has_value(&mapping->serial_number)
	) {
		return TRUE;
	}
	return FALSE;
}


/**
 * @brief Parse a certificate mapping string
 *
 *  The expected format is a header "X509:" and then a series of
 *  tag value pairs "<tag>value"
 *  where tag is one of:
 *     <I>           Issuer Name
 *     <S>           Subject Name
 *     <SR>          Serial Number
 *     <SKI>         SKI Subject Key Identifier
 *     <SHA1-PUKEY>  SHA1 checksum of the public key
 *     <RFC822>      Email address
 *
 *
 * @param[in]  value   ldb value containing an altSecurityIdentities entry
 * @param[out] mapping data parsed from value
 *
 * @note it is the callers responsibility to free any memory allocated
 *       in the mapping with a call to sdb_certificate_mapping_free.
 *       EVEN if an error is returned, as mapping may have been partially
 *       updated.
 *
 * @return 0      No error
 *         EINVAL altSecurityIdentities entry was invalid
 *         ENOMEM memory allocation error
 */
static krb5_error_code parse_certificate_mapping(
	struct ldb_val *ldb_value,
	struct sdb_certificate_mapping *mapping)
{
	krb5_error_code ret = 0;
	size_t length = ldb_value->length;
	uint8_t *data = ldb_value->data;
	DATA_BLOB tag = data_blob_null;
	DATA_BLOB value = data_blob_null;
	enum {
		start_state,
		tag_state,
		value_state
	} state;
	size_t i = 0;

	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	/*
	 * Ensure that there is data, and it starts with X509:
	 * otherwise ignore the entry and return ENOENT
	 */
	if (data == NULL || length == 0) {
		DBG_DEBUG("altSecurityIdentities is empty");
		ret = ENOENT;
		goto out;
	}
	if (length <= X509_HEADER.length ||
	    memcmp(X509_HEADER.data, data, X509_HEADER.length) != 0) {
		DBG_DEBUG("altSecurityIdentities entry is not X509, ignoring");
		ret = ENOENT;
		goto out;
	}

	tag = data_blob_talloc(tmp_ctx, NULL, ldb_value->length + 1);
	if (tag.data == NULL) {
		ret = ENOMEM;
		goto out;
	}
	tag.length = 0;
	value = data_blob_talloc(tmp_ctx, NULL, ldb_value->length + 1);
	if (value.data == NULL) {
		ret = ENOMEM;
		goto out;
	}
	value.length = 0;

	state = start_state;
	/* point to the first byte after the header "X509:" */
	for( i = 5; i < length; i++) {
		uint8_t c = data[i];
		switch (state) {
		case start_state:
			/* Ignore characters between the : and the first < */
			if (c == '<') {
				state = tag_state;
				tag.length = 0;
			}
			break;
		case tag_state:
			if (c == '>') {
				state = value_state;
				tag.data[tag.length] = '\0';
				value.length = 0;
			} else {
				tag.data[tag.length] = c;
				tag.length++;
			}
			break;
		case value_state:
			if (c == '<') {
				value.data[value.length] = '\0';
				ret = populate_certificate_mapping(
					&tag, &value, mapping);
				if (ret != 0) {
					goto out;
				}
				state = tag_state;
				value.length = 0;
				tag.length = 0;
			} else {
				value.data[value.length] = c;
				value.length++;
			}
			break;
		}
	}
	if (state != value_state) {
		DBG_WARNING("altSecurityIdentities expected a value");
		ret = EINVAL;
		goto out;
	}
	value.data[value.length] = '\0';
	ret = populate_certificate_mapping(
		&tag, &value, mapping);
	if (ret != 0) {
		goto out;
	}
	mapping->strong_mapping = is_strong_certificate_mapping(mapping);

out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}


/**
 * @brief extract the certificate mappings for PKINIT from the
 *        ldb message.
 *
 * Processes the "X509:" certificate mappings in altSecurityIdentities.
 *
 * @param mem_ctx[in]	talloc memory context
 * @param lp_ctx[in]	parameter context containing the config options
 * @param msg[in]	ldb message containing the certificate mappings
 * @param entry[out]	entry will be updated with the certificate mappings
 *
 * @note Invalid entries will be ignored
 *
 * @return 0  No error, and there are zero or more certificate mappings
 *         >0 Errors detected
 */
static krb5_error_code get_certificate_mappings(
	TALLOC_CTX *mem_ctx,
	struct loadparm_context *lp_ctx,
	struct ldb_message *msg,
	struct sdb_entry *entry)
{
	krb5_error_code ret = 0;
	struct ldb_message_element *el = NULL;
	size_t i = 0;
	struct sdb_certificate_mappings mappings = {};
	unsigned int backdating = 0;
	time_t created = 0;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	mappings.enforcement_mode =
		lpcfg_strong_certificate_binding_enforcement(lp_ctx);

	backdating = lpcfg_certificate_backdating_compensation(lp_ctx);
	created = ldb_msg_find_krb5time_ldap_time(msg, "whenCreated", 0);
	if (created == 0) {
		DBG_ERR("No whenCreated entry, unable to continue");
		ret = EINVAL;
		goto out;
	}
	mappings.valid_certificate_start = created - (backdating * 60);

	el = ldb_msg_find_element(msg, "altSecurityIdentities");
	if (el == NULL || el->num_values == 0) {
		DBG_DEBUG("No altSecurityIdentities nothing to do");
		ret = 0;
		entry->mappings = mappings;
		goto out;
	}

	for (i = 0; i < el->num_values; i++) {
		struct sdb_certificate_mapping mapping = {};
		ret = parse_certificate_mapping(&el->values[i], &mapping);
		if (ret != 0) {
			DBG_DEBUG("Ignoring invalid altSecurityIdentities"
				  " entry [%*.*s]",
	                          (int)el->values[i].length,
	                          (int)el->values[i].length,
	                          (char *)el->values[i].data);
			sdb_certificate_mapping_free(&mapping);
			continue;
		}
		if (mappings.mappings == NULL) {
			mappings.len = 0;
			mappings.mappings = calloc(1, sizeof(mapping));
			if (mappings.mappings == NULL) {
				sdb_certificate_mapping_free(&mapping);
				ret = ENOMEM;
				goto out;
			}
		} else {
			struct sdb_certificate_mapping *old_mappings =
				mappings.mappings;
			mappings.mappings= realloc_p(
				mappings.mappings,
				struct sdb_certificate_mapping,
				mappings.len + 1);
			if (mappings.mappings == NULL) {
				mappings.mappings = old_mappings;
				sdb_certificate_mappings_free(&mappings);
				sdb_certificate_mapping_free(&mapping);
				ret = ENOMEM;
				goto out;
			}
		}
		mappings.mappings[mappings.len] = mapping;
		mappings.len++;
	}
	entry->mappings = mappings;
	ret = 0;

out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}


/**
 * @brief Extract the KeyMaterial from a KEYCREDENTIALLINK_BLOB
 *        as a KeyMaterialInternal structure.
 *
 * The following validation is performed on the KEYCREDENTIALLINK_BLOB:
 *   1) can be unpacked
 *   2) has one and only one KeyUsage
 *   3) that KeyUsage is KEY_USAGE_NGC
 *   4) has one and only one KeyMaterial
 *   5) that KeyMaterial can be unpacked
 *
 * @param[in] mem_ctx  talloc memory context, that will own pub_key
 * @param[in] ldb      ldb database context
 * @param[in] value    ldb value containing the KEYCREDENTIALLINK_BLOB
 *                         BinaryDn
 * @param[out] pub_key the extracted public key
 *
 * @return 0 No error pub_key will be valid
 *         EINVAL KeyMaterial was invalid, pub_key will be NULL
 *         ENOMEM memory allocation error pub_key will be NULL
 */
static krb5_error_code unpack_key_credential_link_blob(
	TALLOC_CTX *mem_ctx,
	struct ldb_context *ldb,
	struct ldb_val *value,
	struct KeyMaterialInternal **pub_key)
{

	krb5_error_code ret = 0;
	enum ndr_err_code ndr_err = NDR_ERR_SUCCESS;
	struct KEYCREDENTIALLINK_BLOB blob = {};
	DATA_BLOB key_material = data_blob_null;
	struct dsdb_dn *dsdb_dn = NULL;

	int key_usage = 0;

	size_t i = 0;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		*pub_key = NULL;
		return ENOMEM;
	}
	*pub_key = NULL;

	dsdb_dn = dsdb_dn_parse(tmp_ctx, ldb, value, DSDB_SYNTAX_BINARY_DN);
	if (dsdb_dn == NULL) {
		DBG_WARNING("Unable to parse KEYCREDENTIALLINK_BLOB, BinaryDn");
		ret = EINVAL;
		goto out;
	}
	if (dsdb_dn->extra_part.data == NULL ||
	    dsdb_dn->extra_part.length == 0) {
		DBG_WARNING("KEYCREDENTIALLINK_BLOB, BinaryDn is empty");
		ret = EINVAL;
		goto out;
	}

	/* Unpack the KEYCREDENTIALLINK_BLOB */
	ndr_err = ndr_pull_struct_blob_all(
		&dsdb_dn->extra_part,
		tmp_ctx,
		&blob,
		(ndr_pull_flags_fn_t)ndr_pull_KEYCREDENTIALLINK_BLOB);
	if (ndr_err != NDR_ERR_SUCCESS) {
		DBG_WARNING("Unable to unpack KEYCREDENTIALLINK_BLOB, "
			    "ndr_err_code (%d)",
			    ndr_err);
		ret = EINVAL;
		goto out;
	}

	/* No need to check the version as that's checked in the ndr_pull */

	/* get the KeyMaterial and KeyUsage */
	for (i = 0; i < blob.count; i++) {
		struct KEYCREDENTIALLINK_ENTRY *e = NULL;
		e = &blob.entries[i];
		switch (e->identifier) {
		case KeyMaterial:
			if (key_material.data != NULL) {
				DBG_WARNING("Duplicate KeyMaterial");
				ret = EINVAL;
				goto out;
			}
			key_material = e->value.keyMaterial;
			break;
		case KeyUsage:
			if (key_usage != 0) {
				DBG_WARNING("Duplicate KeyUsage");
				ret = EINVAL;
				goto out;
			}
			if (e->value.keyUsage != KEY_USAGE_NGC) {
				DBG_WARNING("Invalid KeyUsage (%d)",
					    e->value.keyUsage);
				ret = EINVAL;
				goto out;
			}
			key_usage = e->value.keyUsage;
			break;
		default:
			break;
		}
	}
	if (key_usage == 0) {
		DBG_WARNING("No KeyUsage");
		ret = EINVAL;
		goto out;
	}
	if (key_material.data == NULL) {
		DBG_WARNING("No KeyMaterial");
		ret = EINVAL;
		goto out;
	}

	/* Unpack the KeyMaterial */
	*pub_key = talloc(mem_ctx, struct KeyMaterialInternal);
	if (*pub_key == NULL) {
		DBG_WARNING("Unable to allocate KeyMaterialInternal");
		ret = ENOMEM;
		goto out;
	}
	ndr_err = ndr_pull_struct_blob_all(
		&key_material,
		mem_ctx,
		*pub_key,
		(ndr_pull_flags_fn_t)ndr_pull_KeyMaterialInternal);
	if (ndr_err != NDR_ERR_SUCCESS) {
		DBG_WARNING("Unable to unpack KeyMaterialInternal, "
			    "ndr_err_code (%d)",
			    ndr_err);
		ret = EINVAL;
		TALLOC_FREE(*pub_key);
		goto out;
	}
	/*
	 * Steal modulus and exponent data from the ndr context onto the pub_key
	 */
	talloc_steal(*pub_key, (*pub_key)->modulus.data);
	talloc_steal(*pub_key, (*pub_key)->exponent.data);

out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

/**
 * @brief extract the public keys for key trust authentication from the
 *        ldb message.
 *
 * Processes the KEYCREDENTIALLINK_BLOBs in the msDS-KeyCredentialLink
 * attribute, extracting all the valid public keys.
 *
 * @param mem_ctx[in] talloc memory context
 * @param ldb[in]     ldb database context
 * @param msg[in]     ldb message containing the public keys
 * @param entry[out]  entry will be updated with the keys
 *
 * @note Invalid KEYCREDENTIALLINK_BLOB's will be ignored
 * @note There may be no public keys, indicating that key trust logon is
 *       not enabled for this object.
 *
 * @return 0  No error, and there are zero or more valid keys in entry
 *         >0 Errors detected
 */
static krb5_error_code get_key_trust_public_keys(TALLOC_CTX *mem_ctx,
						 struct ldb_context *ldb,
						 struct ldb_message *msg,
						 struct sdb_entry *entry)
{
	krb5_error_code ret = 0;
	struct ldb_message_element *el = NULL;
	size_t i = 0;
	struct sdb_pub_keys pub_keys = {};

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	el = ldb_msg_find_element(msg, "msDS-KeyCredentialLink");
	if (el == NULL || el->num_values == 0) {
		/* No msDS-KeyCredentialLink nothing to do */
		goto out;
	}

	for (i = 0; i < el->num_values; i++) {
		krb5_error_code r = 0;
		struct KeyMaterialInternal *kmi = NULL;
		struct sdb_pub_key pub_key = {};
		r = unpack_key_credential_link_blob(tmp_ctx,
						    ldb,
						    &el->values[i],
						    &kmi);
		if (r == 0) {
			/* Get bit size*/
			pub_key.bit_size = kmi->bit_size;

			/* get Exponent */
			pub_key.exponent.length = kmi->exponent.length;
			pub_key.exponent.data = malloc(kmi->exponent.length);
			if (pub_key.exponent.data == NULL) {
				goto pub_keys_oom;
			}
			memcpy(pub_key.exponent.data,
			       kmi->exponent.data,
			       kmi->exponent.length);

			/* get Modulus */
			pub_key.modulus.length = kmi->modulus.length;
			pub_key.modulus.data = malloc(kmi->modulus.length);
			if (pub_key.modulus.data == NULL) {
					SAFE_FREE(pub_key.exponent.data);
					goto pub_keys_oom;
			}
			memcpy(pub_key.modulus.data,
			       kmi->modulus.data,
			       kmi->modulus.length);

			/* Add public key to the list of public keys */
			if (pub_keys.keys == NULL) {
				pub_keys.len = 0;
				pub_keys.keys = calloc(1, sizeof(pub_key));
				if (pub_keys.keys == NULL) {
					SAFE_FREE(pub_key.exponent.data);
					SAFE_FREE(pub_key.modulus.data);
					goto pub_keys_oom;
				}
			} else {
				struct sdb_pub_key *keys = realloc_p(
					pub_keys.keys,
					struct sdb_pub_key,
					pub_keys.len + 1);
				if (keys == NULL) {
					SAFE_FREE(pub_key.exponent.data);
					SAFE_FREE(pub_key.modulus.data);
					goto pub_keys_oom;
				}
				pub_keys.keys = keys;
			}
			pub_keys.keys[pub_keys.len] = pub_key;
			pub_keys.len++;
		}
		TALLOC_FREE(kmi);
	}
	if (pub_keys.len != 0) {
		entry->pub_keys = pub_keys;
	}
	goto out;

pub_keys_oom:
	sdb_pub_keys_free(&pub_keys);
	ret = ENOMEM;

out:
	TALLOC_FREE(tmp_ctx);
	return ret;
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
					       krb5_kvno kvno,
					       struct ldb_dn *realm_dn,
					       struct ldb_message *msg,
					       struct sdb_entry *entry)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct loadparm_context *lp_ctx = kdc_db_ctx->lp_ctx;
	uint32_t userAccountControl;
	uint32_t msDS_User_Account_Control_Computed;
	krb5_error_code ret = 0;
	krb5_boolean is_computer = FALSE;
	struct samba_kdc_entry *p;
	NTTIME acct_expiry;
	NTSTATUS status;
	bool protected_user = false;
	uint32_t rid;
	bool is_krbtgt = false;
	bool is_rodc = false;
	bool force_rc4 = lpcfg_kdc_force_enable_rc4_weak_session_keys(lp_ctx);
	struct ldb_message_element *objectclasses;
	struct ldb_val computer_val = data_blob_string_const("computer");
	struct ldb_val gmsa_oc_val = data_blob_string_const("msDS-GroupManagedServiceAccount");
	uint32_t config_default_supported_enctypes = lpcfg_kdc_default_domain_supported_enctypes(lp_ctx);
	uint32_t default_supported_enctypes =
		config_default_supported_enctypes != 0 ?
		config_default_supported_enctypes :
		ENC_RC4_HMAC_MD5 | ENC_HMAC_SHA1_96_AES256_SK;
	uint32_t supported_enctypes
		= ldb_msg_find_attr_as_uint(msg,
					    "msDS-SupportedEncryptionTypes",
					    default_supported_enctypes);
	uint32_t pa_supported_enctypes;
	uint32_t supported_session_etypes;
	uint32_t available_enctypes = 0;
	/*
	 * also legacy enctypes are announced,
	 * but effectively restricted by kdc_enctypes
	 */
	uint32_t domain_enctypes = ENC_RC4_HMAC_MD5 | ENC_RSA_MD5 | ENC_CRC32;
	uint32_t config_kdc_enctypes = lpcfg_kdc_supported_enctypes(lp_ctx);
	uint32_t kdc_enctypes =
		config_kdc_enctypes != 0 ?
		config_kdc_enctypes :
		ENC_ALL_TYPES;
	const char *samAccountName = ldb_msg_find_attr_as_string(msg, "sAMAccountName", NULL);

	const struct authn_kerberos_client_policy *authn_client_policy = NULL;
	const struct authn_server_policy *authn_server_policy = NULL;
	const bool user2user = (flags & SDB_F_USER2USER_PRINCIPAL);
	int64_t lifetime_secs;
	int effective_lifetime_secs;

	*entry = (struct sdb_entry) {};

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	if (supported_enctypes == 0) {
		supported_enctypes = default_supported_enctypes;
	}

	if (dsdb_functional_level(kdc_db_ctx->samdb) >= DS_DOMAIN_FUNCTION_2008) {
		domain_enctypes |= ENC_HMAC_SHA1_96_AES128 | ENC_HMAC_SHA1_96_AES256;
	}

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

	p = talloc_zero(tmp_ctx, struct samba_kdc_entry);
	if (!p) {
		ret = ENOMEM;
		goto out;
	}

	if (objectclasses && ldb_msg_find_val(objectclasses, &gmsa_oc_val)) {
		p->group_managed_service_account = true;
	}

	p->is_rodc = is_rodc;
	p->kdc_db_ctx = kdc_db_ctx;
	p->realm_dn = talloc_reference(p, realm_dn);
	if (!p->realm_dn) {
		ret = ENOMEM;
		goto out;
	}
	p->current_nttime = *kdc_db_ctx->current_nttime_ull;

	talloc_set_destructor(p, samba_kdc_entry_destructor);

	entry->skdc_entry = p;

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

	if (ent_type == SAMBA_KDC_ENT_TYPE_KRBTGT) {
		p->is_krbtgt = true;
	}

	/* First try and figure out the flags based on the userAccountControl */
	entry->flags = uf2SDBFlags(context, userAccountControl, ent_type);

	/*
	 * Take control of the returned principal here, rather than
	 * allowing the Heimdal code to do it as we have specific
	 * behaviour around the forced realm to honour
	 */
	entry->flags.force_canonicalize = true;

	/*
	 * Windows 2008 seems to enforce this (very sensible) rule by
	 * default - don't allow offline attacks on a user's password
	 * by asking for a ticket to them as a service (encrypted with
	 * their probably pathetically insecure password)
	 *
	 * But user2user avoids using the keys based on the password,
	 * so we can allow it.
	 */

	if (entry->flags.server && !user2user
	    && lpcfg_parm_bool(lp_ctx, NULL, "kdc", "require spn for service", true)) {
		if (!is_computer && !ldb_msg_find_attr_as_string(msg, "servicePrincipalName", NULL)) {
			entry->flags.server = 0;
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
		char *third_part = NULL;
		bool is_our_realm;
		bool is_dc;

		ret = smb_krb5_principal_get_comp_string(tmp_ctx,
							 context,
							 principal,
							 2,
							 &third_part);
		if (ret) {
			krb5_set_error_message(context, ret, "smb_krb5_principal_get_comp_string: out of memory");
			goto out;
		}

		is_our_realm = lpcfg_is_my_domain_or_realm(lp_ctx,
						     third_part);
		is_dc = userAccountControl &
			(UF_SERVER_TRUST_ACCOUNT | UF_PARTIAL_SECRETS_ACCOUNT);
		if (is_our_realm && !is_dc) {
			entry->flags.server = 0;
		}
	}
	/*
	 * To give the correct type of error to the client, we must
	 * not just return the entry without .server set, we must
	 * pretend the principal does not exist.  Otherwise we may
	 * return ERR_POLICY instead of
	 * KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN
	 */
	if (ent_type == SAMBA_KDC_ENT_TYPE_SERVER && entry->flags.server == 0) {
		ret = SDB_ERR_NOENTRY;
		krb5_set_error_message(context, ret, "samba_kdc_message2entry: no servicePrincipalName present for this server, refusing with no-such-entry");
		goto out;
	}
	if (flags & SDB_F_ADMIN_DATA) {
		/* These (created_by, modified_by) parts of the entry are not relevant for Samba4's use
		 * of the Heimdal KDC.  They are stored in the traditional
		 * DB for audit purposes, and still form part of the structure
		 * we must return */

		/* use 'whenCreated' */
		entry->created_by.time = ldb_msg_find_krb5time_ldap_time(msg, "whenCreated", 0);
		/* use 'kadmin' for now (needed by mit_samba) */

		ret = smb_krb5_make_principal(context,
					      &entry->created_by.principal,
					      lpcfg_realm(lp_ctx), "kadmin", NULL);
		if (ret) {
			krb5_clear_error_message(context);
			goto out;
		}

		entry->modified_by = calloc(1, sizeof(struct sdb_event));
		if (entry->modified_by == NULL) {
			ret = ENOMEM;
			krb5_set_error_message(context, ret, "calloc: out of memory");
			goto out;
		}

		/* use 'whenChanged' */
		entry->modified_by->time = ldb_msg_find_krb5time_ldap_time(msg, "whenChanged", 0);
		/* use 'kadmin' for now (needed by mit_samba) */
		ret = smb_krb5_make_principal(context,
					      &entry->modified_by->principal,
					      lpcfg_realm(lp_ctx), "kadmin", NULL);
		if (ret) {
			krb5_clear_error_message(context);
			goto out;
		}
	}


	/* The lack of password controls etc applies to krbtgt by
	 * virtue of being that particular RID */
	ret = samdb_result_dom_sid_buf(msg, "objectSid", &entry->sid);
	if (ret) {
		goto out;
	}
	status = dom_sid_split_rid(NULL, &entry->sid, NULL, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		ret = EINVAL;
		goto out;
	}

	if (rid == DOMAIN_RID_KRBTGT) {
		char *realm = NULL;

		entry->valid_end = NULL;
		entry->pw_end = NULL;

		entry->flags.invalid = 0;
		entry->flags.server = 1;

		realm = smb_krb5_principal_get_realm(
			tmp_ctx, context, principal);
		if (realm == NULL) {
			ret = ENOMEM;
			goto out;
		}

		/* Don't mark all requests for the krbtgt/realm as
		 * 'change password', as otherwise we could get into
		 * trouble, and not enforce the password expiry.
		 * Instead, only do it when request is for the kpasswd service */
		if (ent_type == SAMBA_KDC_ENT_TYPE_SERVER) {
			bool is_changepw = false;

			ret = is_kadmin_changepw(context, principal, &is_changepw);
			if (ret) {
				goto out;
			}

			if (is_changepw && lpcfg_is_my_domain_or_realm(lp_ctx, realm)) {
				entry->flags.change_pw = 1;
			}
		}

		TALLOC_FREE(realm);

		entry->flags.client = 0;
		entry->flags.forwardable = 1;
		entry->flags.ok_as_delegate = 1;
	} else if (is_rodc) {
		/* The RODC krbtgt account is like the main krbtgt,
		 * but it does not have a changepw or kadmin
		 * service */

		entry->valid_end = NULL;
		entry->pw_end = NULL;

		/* Also don't allow the RODC krbtgt to be a client (it should not be needed) */
		entry->flags.client = 0;
		entry->flags.invalid = 0;
		entry->flags.server = 1;

		entry->flags.client = 0;
		entry->flags.forwardable = 1;
		entry->flags.ok_as_delegate = 0;
	} else if (entry->flags.server && ent_type == SAMBA_KDC_ENT_TYPE_SERVER) {
		/* The account/password expiry only applies when the account is used as a
		 * client (ie password login), not when used as a server */

		/* Make very well sure we don't use this for a client,
		 * it could bypass the password restrictions */
		entry->flags.client = 0;

		entry->valid_end = NULL;
		entry->pw_end = NULL;

	} else {
		NTTIME must_change_time
			= samdb_result_nttime(msg,
					"msDS-UserPasswordExpiryTimeComputed",
					0);
		if (must_change_time == 0x7FFFFFFFFFFFFFFFULL) {
			entry->pw_end = NULL;
		} else {
			entry->pw_end = malloc(sizeof(*entry->pw_end));
			if (entry->pw_end == NULL) {
				ret = ENOMEM;
				goto out;
			}
			*entry->pw_end = nt_time_to_unix(must_change_time);
		}

		acct_expiry = samdb_result_account_expires(msg);
		if (acct_expiry == 0x7FFFFFFFFFFFFFFFULL) {
			entry->valid_end = NULL;
		} else {
			entry->valid_end = malloc(sizeof(*entry->valid_end));
			if (entry->valid_end == NULL) {
				ret = ENOMEM;
				goto out;
			}
			*entry->valid_end = nt_time_to_unix(acct_expiry);
		}
	}

	ret = samba_kdc_get_entry_principal(context,
					    kdc_db_ctx,
					    samAccountName,
					    ent_type,
					    flags,
					    entry->flags.change_pw,
					    principal,
					    &entry->principal);
	if (ret != 0) {
		krb5_clear_error_message(context);
		goto out;
	}

	entry->valid_start = NULL;

	entry->max_life = malloc(sizeof(*entry->max_life));
	if (entry->max_life == NULL) {
		ret = ENOMEM;
		goto out;
	}

	if (ent_type == SAMBA_KDC_ENT_TYPE_SERVER) {
		*entry->max_life = kdc_db_ctx->policy.svc_tkt_lifetime;
	} else if (ent_type == SAMBA_KDC_ENT_TYPE_KRBTGT || ent_type == SAMBA_KDC_ENT_TYPE_CLIENT) {
		*entry->max_life = kdc_db_ctx->policy.usr_tkt_lifetime;
	} else {
		*entry->max_life = MIN(kdc_db_ctx->policy.svc_tkt_lifetime,
					        kdc_db_ctx->policy.usr_tkt_lifetime);
	}

	if (entry->flags.change_pw) {
		/* Limit lifetime of kpasswd tickets to two minutes or less. */
		*entry->max_life = MIN(*entry->max_life, CHANGEPW_LIFETIME);
	}

	entry->max_renew = malloc(sizeof(*entry->max_renew));
	if (entry->max_renew == NULL) {
		ret = ENOMEM;
		goto out;
	}

	*entry->max_renew = kdc_db_ctx->policy.renewal_lifetime;

	/*
	 * A principal acting as a client that is not being looked up as the
	 * principal of an armor ticket may have an authentication policy apply
	 * to it.
	 *
	 * We won’t get an authentication policy for the client of an S4U2Self
	 * or S4U2Proxy request. Those clients are looked up with
	 * SDB_F_FOR_TGS_REQ instead of with SDB_F_FOR_AS_REQ.
	 */
	if (ent_type == SAMBA_KDC_ENT_TYPE_CLIENT &&
	    (flags & SDB_F_FOR_AS_REQ) &&
	    !(flags & SDB_F_ARMOR_PRINCIPAL))
	{
		ret = authn_policy_kerberos_client(kdc_db_ctx->samdb, tmp_ctx, msg,
						   &authn_client_policy);
		if (ret) {
			goto out;
		}
	}

	/*
	 * A principal acting as a server may have an authentication policy
	 * apply to it.
	 */
	if (ent_type == SAMBA_KDC_ENT_TYPE_SERVER) {
		ret = authn_policy_server(kdc_db_ctx->samdb, tmp_ctx, msg,
					  &authn_server_policy);
		if (ret) {
			goto out;
		}
	}

	entry->skdc_entry->enforced_tgt_lifetime_nt_ticks = authn_policy_enforced_tgt_lifetime_raw(authn_client_policy);
	lifetime_secs = entry->skdc_entry->enforced_tgt_lifetime_nt_ticks;
	effective_lifetime_secs = *entry->max_life;

	if (lifetime_secs != 0) {
		lifetime_secs /= INT64_C(1000) * 1000 * 10;
		lifetime_secs = MIN(lifetime_secs, INT_MAX);
		lifetime_secs = MAX(lifetime_secs, INT_MIN);

		effective_lifetime_secs = MIN(effective_lifetime_secs,
					      lifetime_secs);

		/*
		 * Set both lifetime and renewal time based only on the
		 * configured maximum lifetime — not on the configured renewal
		 * time. Yes, this is what Windows does.
		 */
		*entry->max_life = effective_lifetime_secs;
		*entry->max_renew = effective_lifetime_secs;
	}

	if (ent_type == SAMBA_KDC_ENT_TYPE_CLIENT && (flags & SDB_F_FOR_AS_REQ)) {
		int result;
		const struct auth_user_info_dc *user_info_dc = NULL;
		/*
		 * These protections only apply to clients, so servers in the
		 * Protected Users group may still have service tickets to them
		 * encrypted with RC4. For accounts looked up as servers, note
		 * that 'msg' does not contain the 'memberOf' attribute for
		 * determining whether the account is a member of Protected
		 * Users.
		 *
		 * Additionally, Microsoft advises that accounts for services
		 * and computers should never be members of Protected Users, or
		 * they may fail to authenticate.
		 */
		ret = samba_kdc_get_user_info_from_db(tmp_ctx,
						      kdc_db_ctx,
						      p,
						      msg,
						      &user_info_dc);
		if (ret) {
			goto out;
		}

		result = dsdb_is_protected_user(kdc_db_ctx->samdb,
						user_info_dc->sids,
						user_info_dc->num_sids);
		if (result == -1) {
			ret = EINVAL;
			goto out;
		}

		protected_user = result;

		if (protected_user) {
			entry->flags.forwardable = 0;
			entry->flags.proxiable = 0;

			if (lifetime_secs == 0) {
				/*
				 * If a TGT lifetime hasn’t been set, Protected
				 * Users enforces a four hour TGT lifetime.
				 */

				effective_lifetime_secs = 4 * 60 * 60;

				*entry->max_life = MIN(*entry->max_life, effective_lifetime_secs);
				*entry->max_renew = MIN(*entry->max_renew, effective_lifetime_secs);
			}
		}
	}

	if (effective_lifetime_secs != lifetime_secs) {
		/*
		 * Since ‘effective_lifetime_secs’ has changed, update
		 * ‘enforced_tgt_lifetime_nt_ticks’ to match.
		 */
		entry->skdc_entry->enforced_tgt_lifetime_nt_ticks =
			effective_lifetime_secs * (INT64_C(1000) * 1000 * 10);
	}

	if (rid == DOMAIN_RID_KRBTGT || is_rodc) {
		bool enable_fast;

		is_krbtgt = true;

		/*
		 * KDCs (and KDCs on RODCs)
		 * ignore msDS-SupportedEncryptionTypes completely
		 * but support all supported enctypes by the domain.
		 */
		supported_enctypes = domain_enctypes;

		enable_fast = lpcfg_kdc_enable_fast(kdc_db_ctx->lp_ctx);
		if (enable_fast) {
			supported_enctypes |= ENC_FAST_SUPPORTED;
		}

		supported_enctypes |= ENC_CLAIMS_SUPPORTED;
		supported_enctypes |= ENC_COMPOUND_IDENTITY_SUPPORTED;

		/*
		 * Resource SID compression is enabled implicitly, unless
		 * disabled in msDS-SupportedEncryptionTypes.
		 */

	} else if (userAccountControl & (UF_PARTIAL_SECRETS_ACCOUNT|UF_SERVER_TRUST_ACCOUNT)) {
		/*
		 * DCs and RODCs computer accounts take
		 * msDS-SupportedEncryptionTypes unmodified, but
		 * force all enctypes supported by the domain.
		 */
		supported_enctypes |= domain_enctypes;

	} else if (ent_type == SAMBA_KDC_ENT_TYPE_CLIENT ||
		   (ent_type == SAMBA_KDC_ENT_TYPE_ANY)) {
		/*
		 * for AS-REQ the client chooses the enc types it
		 * supports, and this will vary between computers a
		 * user logs in from. Therefore, so that we accept any
		 * of the client's keys for decrypting padata,
		 * supported_enctypes should not restrict etype usage.
		 *
		 * likewise for 'any' return as much as is supported,
		 * to export into a keytab.
		 */
		supported_enctypes |= ENC_ALL_TYPES;
	}

	/* If UF_USE_DES_KEY_ONLY has been set, then don't allow use of the newer enc types */
	if (userAccountControl & UF_USE_DES_KEY_ONLY) {
		supported_enctypes &= ~ENC_ALL_TYPES;
		DBG_NOTICE("DES-only keys allowed on the account '%s', "
			   "most likely auth will fail through Kerberos\n",
			   samAccountName);
	}

	if (protected_user) {
		supported_enctypes &= ~ENC_RC4_HMAC_MD5;
	}

	pa_supported_enctypes = supported_enctypes;
	supported_session_etypes = supported_enctypes;
	if (supported_session_etypes & ENC_HMAC_SHA1_96_AES256_SK) {
		supported_session_etypes |= ENC_HMAC_SHA1_96_AES256;
		supported_session_etypes |= ENC_HMAC_SHA1_96_AES128;
	}
	if (force_rc4) {
		supported_session_etypes |= ENC_RC4_HMAC_MD5;
	}
	/*
	 * now that we remembered what to announce in pa_supported_enctypes
	 * and normalized ENC_HMAC_SHA1_96_AES256_SK, we restrict the
	 * rest to the enc types the local kdc supports.
	 */
	supported_enctypes &= kdc_enctypes;
	supported_session_etypes &= kdc_enctypes;

	/* Get keys from the db */
	ret = samba_kdc_message2entry_keys(context, p,
					   kdc_db_ctx->samdb, msg,
					   is_krbtgt, is_rodc,
					   userAccountControl,
					   ent_type, flags, kvno, entry,
					   supported_enctypes,
					   &available_enctypes);
	if (ret) {
		/* Could be bogus data in the entry, or out of memory */
		goto out;
	}

	/*
	 * If we only have a nthash stored,
	 * but a better session key would be
	 * available, we fallback to fetching the
	 * RC4_HMAC_MD5, which implicitly also
	 * would allow an RC4_HMAC_MD5 session key.
	 * But only if the kdc actually supports
	 * RC4_HMAC_MD5.
	 */
	if (available_enctypes == 0 &&
	    (supported_enctypes & ENC_RC4_HMAC_MD5) == 0 &&
	    (supported_enctypes & ~ENC_RC4_HMAC_MD5) != 0 &&
	    (kdc_enctypes & ENC_RC4_HMAC_MD5) != 0)
	{
		supported_enctypes = ENC_RC4_HMAC_MD5;
		ret = samba_kdc_message2entry_keys(context, p,
						   kdc_db_ctx->samdb, msg,
						   is_krbtgt, is_rodc,
						   userAccountControl,
						   ent_type, flags, kvno, entry,
						   supported_enctypes,
						   &available_enctypes);
		if (ret) {
			/* Could be bogus data in the entry, or out of memory */
			goto out;
		}
	}

	/*
	 * We need to support all session keys enctypes for
	 * all keys we provide
	 */
	supported_session_etypes |= available_enctypes;

	ret = sdb_entry_set_etypes(entry);
	if (ret) {
		goto out;
	}

	if (entry->flags.server) {
		bool add_aes256 =
			supported_session_etypes & KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96;
		bool add_aes128 =
			supported_session_etypes & KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96;
		bool add_rc4 =
			supported_session_etypes & ENC_RC4_HMAC_MD5;
		ret = sdb_entry_set_session_etypes(entry,
						   add_aes256,
						   add_aes128,
						   add_rc4);
		if (ret) {
			goto out;
		}
	}

	if (entry->keys.len != 0) {
		/*
		 * FIXME: Currently limited to Heimdal so as not to
		 * break MIT KDCs, for which no fix is available.
		 */
#ifdef SAMBA4_USES_HEIMDAL
		if (is_krbtgt) {
			unsigned int i = 0;

			/*
			 * The krbtgt account, having no reason to
			 * issue tickets encrypted in weaker keys,
			 * shall only make available its strongest
			 * key. All weaker keys are stripped out. This
			 * makes it impossible for an RC4-encrypted
			 * TGT to be accepted when AES KDC keys exist.
			 *
			 * This controls the ticket key and so the PAC
			 * signature algorithms indirectly, preventing
			 * a weak KDC checksum from being accepted
			 * when we verify the signatures for an
			 * S4U2Proxy evidence ticket. As such, this is
			 * indispensable for addressing
			 * CVE-2022-37966.
			 *
			 * Being strict here also provides protection
			 * against possible future attacks on weak
			 * keys.
			 */

			/*
			 * The krbtgt account is never a Group Managed Service
			 * Account, but a similar system might well be
			 * implemented as a means of having the krbtgt’s keys
			 * roll over automatically. In that case, thought might
			 * be given as to how this security measure — of
			 * stripping out weaker keys — would interact with key
			 * management.
			 */

			for (i = 1; i < entry->keys.len; i++) {
				sdb_key_free(&entry->keys.val[i]);
			}
			entry->keys.len = 1;
			if (entry->etypes != NULL) {
				entry->etypes->len = MIN(entry->etypes->len, 1);
			}
			for (i = 1; i < entry->old_keys.len; i++) {
				sdb_key_free(&entry->old_keys.val[i]);
			}
			entry->old_keys.len = MIN(entry->old_keys.len, 1);
			for (i = 1; i < entry->older_keys.len; i++) {
				sdb_key_free(&entry->older_keys.val[i]);
			}
			entry->older_keys.len = MIN(entry->older_keys.len, 1);
		}
#endif
	} else if (kdc_db_ctx->rodc) {
		/*
		 * We are on an RODC, but don't have keys for this
		 * account.  Signal this to the caller
		 */
		auth_sam_trigger_repl_secret(kdc_db_ctx,
					     kdc_db_ctx->msg_ctx,
					     kdc_db_ctx->ev_ctx,
					     msg->dn);
		ret = SDB_ERR_NOT_FOUND_HERE;
		goto out;
	} else {
		/*
		 * oh, no password.  Apparently (comment in
		 * hdb-ldap.c) this violates the ASN.1, but this
		 * allows an entry with no keys (yet).
		 */
	}

	ret = get_key_trust_public_keys(tmp_ctx, kdc_db_ctx->samdb, msg, entry);
	if (ret != 0) {
		goto out;
	}
	ret = get_certificate_mappings(
		tmp_ctx, kdc_db_ctx->lp_ctx, msg, entry);
	if (ret != 0) {
		goto out;
	}

	p->msg = talloc_steal(p, msg);
	p->supported_enctypes = pa_supported_enctypes;

	p->client_policy = talloc_steal(p, authn_client_policy);
	p->server_policy = talloc_steal(p, authn_server_policy);

	talloc_steal(kdc_db_ctx, p);

out:
	if (ret != 0) {
		/* This doesn't free ent itself, that is for the eventual caller to do */
		sdb_entry_free(entry);
	}

	talloc_free(tmp_ctx);
	return ret;
}

struct samba_kdc_trust_keys {
	struct sdb_keys *skeys;
	uint32_t kvno;
	uint32_t *returned_kvno;
	uint32_t supported_enctypes;
	uint32_t *available_enctypes;
	krb5_const_principal salt_principal;
	const struct AuthenticationInformationArray *auth_array;
};

static krb5_error_code samba_kdc_fill_trust_keys(krb5_context context,
						 struct samba_kdc_trust_keys *p)
{
	/*
	 * Make sure we'll never reveal DES keys
	 */
	uint32_t supported_enctypes = p->supported_enctypes &= ~(ENC_CRC32 | ENC_RSA_MD5);
	uint32_t _available_enctypes = 0;
	uint32_t *available_enctypes = p->available_enctypes;
	uint32_t _returned_kvno = 0;
	uint32_t *returned_kvno = p->returned_kvno;
	TALLOC_CTX *frame = talloc_stackframe();
	const struct AuthenticationInformationArray *aa = p->auth_array;
	DATA_BLOB password_utf16 = { .length = 0, };
	DATA_BLOB password_utf8 = { .length = 0, };
	struct samr_Password _password_hash = { .hash = { 0,}, };
	const struct samr_Password *password_hash = NULL;
	uint32_t allocated_keys = 0;
	uint32_t i;
	int ret;

	if (available_enctypes == NULL) {
		available_enctypes = &_available_enctypes;
	}

	*available_enctypes = 0;

	if (returned_kvno == NULL) {
		returned_kvno = &_returned_kvno;
	}

	*returned_kvno = p->kvno;

	for (i=0; i < aa->count; i++) {
		if (aa->array[i].AuthType == TRUST_AUTH_TYPE_CLEAR) {
			const struct AuthInfoClear *clear =
				&aa->array[i].AuthInfo.clear;
			bool ok;

			password_utf16 = data_blob_const(clear->password,
							 clear->size);
			if (password_utf16.length == 0) {
				break;
			}

			if (supported_enctypes & ENC_RC4_HMAC_MD5) {
				mdfour(_password_hash.hash,
				       password_utf16.data,
				       password_utf16.length);
				if (password_hash == NULL) {
					allocated_keys += 1;
				}
				password_hash = &_password_hash;
			}

			if (!(supported_enctypes & (ENC_HMAC_SHA1_96_AES128|ENC_HMAC_SHA1_96_AES256))) {
				break;
			}

			ok = convert_string_talloc(frame,
						   CH_UTF16MUNGED, CH_UTF8,
						   password_utf16.data,
						   password_utf16.length,
						   &password_utf8.data,
						   &password_utf8.length);
			if (!ok) {
				krb5_clear_error_message(context);
				ret = ENOMEM;
				goto fail;
			}

			if (supported_enctypes & ENC_HMAC_SHA1_96_AES128) {
				allocated_keys += 1;
			}
			if (supported_enctypes & ENC_HMAC_SHA1_96_AES256) {
				allocated_keys += 1;
			}
			break;
		} else if (aa->array[i].AuthType == TRUST_AUTH_TYPE_NT4OWF) {
			const struct AuthInfoNT4Owf *nt4owf =
				&aa->array[i].AuthInfo.nt4owf;

			if (supported_enctypes & ENC_RC4_HMAC_MD5) {
				password_hash = &nt4owf->password;
				allocated_keys += 1;
			}
		}
	}

	allocated_keys = MAX(1, allocated_keys);

	/* allocate space to decode into */
	p->skeys->len = 0;
	p->skeys->val = calloc(allocated_keys, sizeof(struct sdb_key));
	if (p->skeys->val == NULL) {
		krb5_clear_error_message(context);
		ret = ENOMEM;
		goto fail;
	}

	if (password_utf8.length != 0) {
		struct sdb_key key = {};
		krb5_data salt;
		krb5_data cleartext_data;

		cleartext_data.data = discard_const_p(char, password_utf8.data);
		cleartext_data.length = password_utf8.length;

		ret = smb_krb5_get_pw_salt(context,
					   p->salt_principal,
					   &salt);
		if (ret != 0) {
			goto fail;
		}

		if (supported_enctypes & ENC_HMAC_SHA1_96_AES256) {
			key.salt = calloc(1, sizeof(*key.salt));
			if (key.salt == NULL) {
				smb_krb5_free_data_contents(context, &salt);
				ret = ENOMEM;
				goto fail;
			}

			key.salt->type = KRB5_PW_SALT;

			ret = smb_krb5_copy_data_contents(&key.salt->salt,
							  salt.data,
							  salt.length);
			if (ret) {
				*key.salt = (struct sdb_salt) {};
				sdb_key_free(&key);
				smb_krb5_free_data_contents(context, &salt);
				goto fail;
			}

			ret = smb_krb5_create_key_from_string(context,
							      p->salt_principal,
							      &salt,
							      &cleartext_data,
							      ENCTYPE_AES256_CTS_HMAC_SHA1_96,
							      &key.key);
			if (ret == 0) {
				p->skeys->val[p->skeys->len++] = key;
				*available_enctypes |= ENC_HMAC_SHA1_96_AES256;
			} else if (ret == KRB5_PROG_ETYPE_NOSUPP) {
				DBG_NOTICE("Unsupported keytype ignored - type %u\n",
					   ENCTYPE_AES256_CTS_HMAC_SHA1_96);
				ZERO_STRUCT(key.key);
				sdb_key_free(&key);
				ret = 0;
			}
			if (ret != 0) {
				ZERO_STRUCT(key.key);
				sdb_key_free(&key);
				smb_krb5_free_data_contents(context, &salt);
				goto fail;
			}
		}

		if (supported_enctypes & ENC_HMAC_SHA1_96_AES128) {
			key.salt = calloc(1, sizeof(*key.salt));
			if (key.salt == NULL) {
				smb_krb5_free_data_contents(context, &salt);
				ret = ENOMEM;
				goto fail;
			}

			key.salt->type = KRB5_PW_SALT;

			ret = smb_krb5_copy_data_contents(&key.salt->salt,
							  salt.data,
							  salt.length);
			if (ret) {
				*key.salt = (struct sdb_salt) {};
				sdb_key_free(&key);
				smb_krb5_free_data_contents(context, &salt);
				goto fail;
			}

			ret = smb_krb5_create_key_from_string(context,
							      p->salt_principal,
							      &salt,
							      &cleartext_data,
							      ENCTYPE_AES128_CTS_HMAC_SHA1_96,
							      &key.key);
			if (ret == 0) {
				p->skeys->val[p->skeys->len++] = key;
				*available_enctypes |= ENC_HMAC_SHA1_96_AES128;
			} else if (ret == KRB5_PROG_ETYPE_NOSUPP) {
				DBG_NOTICE("Unsupported keytype ignored - type %u\n",
					   ENCTYPE_AES128_CTS_HMAC_SHA1_96);
				ZERO_STRUCT(key.key);
				sdb_key_free(&key);
				ret = 0;
			}
			if (ret != 0) {
				ZERO_STRUCT(key.key);
				sdb_key_free(&key);
				smb_krb5_free_data_contents(context, &salt);
				goto fail;
			}
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
		if (ret == 0) {
			p->skeys->val[p->skeys->len++] = key;

			*available_enctypes |= ENC_RC4_HMAC_MD5;
		} else if (ret == KRB5_PROG_ETYPE_NOSUPP) {
			DEBUG(2,("Unsupported keytype ignored - type %u\n",
				 ENCTYPE_ARCFOUR_HMAC));
			ZERO_STRUCT(key.key);
			sdb_key_free(&key);
			ret = 0;
		}
		if (ret != 0) {
			ZERO_STRUCT(key.key);
			sdb_key_free(&key);
			goto fail;
		}
	}

	samba_kdc_sort_keys(p->skeys);

	return 0;
fail:
	sdb_keys_free(p->skeys);
	TALLOC_FREE(frame);
	return ret;
}

/*
 * Construct an hdb_entry from a directory entry.
 * The kvno is what the remote client asked for
 */
static krb5_error_code samba_kdc_trust_message2entry(krb5_context context,
					       struct samba_kdc_db_context *kdc_db_ctx,
					       TALLOC_CTX *mem_ctx,
					       enum trust_direction direction,
					       struct ldb_dn *realm_dn,
					       unsigned flags,
					       uint32_t kvno,
					       struct ldb_message *msg,
					       struct sdb_entry *entry)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct loadparm_context *lp_ctx = kdc_db_ctx->lp_ctx;
	const char *our_realm = lpcfg_realm(lp_ctx);
	char *partner_realm = NULL;
	const char *realm = NULL;
	const char *krbtgt_realm = NULL;
	const struct ldb_val *password_val;
	struct trustAuthInOutBlob password_blob;
	struct samba_kdc_entry *p;
	bool use_previous = false;
	bool include_previous = false;
	uint32_t current_kvno;
	uint32_t previous_kvno;
	struct samba_kdc_trust_keys current_keys = {};
	struct samba_kdc_trust_keys previous_keys = {};
	enum ndr_err_code ndr_err;
	int ret;
	unsigned int i;
	NTTIME now = *kdc_db_ctx->current_nttime_ull;
	NTTIME an_hour_ago, an_hour;
	bool prefer_current = false;
	bool force_rc4 = lpcfg_kdc_force_enable_rc4_weak_session_keys(lp_ctx);
	uint32_t supported_enctypes = ENC_RC4_HMAC_MD5;
	uint32_t pa_supported_enctypes;
	uint32_t supported_session_etypes;
	uint32_t config_kdc_enctypes = lpcfg_kdc_supported_enctypes(lp_ctx);
	uint32_t kdc_enctypes =
		config_kdc_enctypes != 0 ?
		config_kdc_enctypes :
		ENC_ALL_TYPES;
	struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
	NTSTATUS status;
	uint32_t returned_kvno = 0;
	uint32_t available_enctypes = 0;

	*entry = (struct sdb_entry) {};

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	if (dsdb_functional_level(kdc_db_ctx->samdb) >= DS_DOMAIN_FUNCTION_2008) {
		/* If not told otherwise, Windows now assumes that trusts support AES. */
		supported_enctypes = ldb_msg_find_attr_as_uint(msg,
					"msDS-SupportedEncryptionTypes",
					ENC_HMAC_SHA1_96_AES256);
	}

	pa_supported_enctypes = supported_enctypes;
	supported_session_etypes = supported_enctypes;
	if (supported_session_etypes & ENC_HMAC_SHA1_96_AES256_SK) {
		supported_session_etypes |= ENC_HMAC_SHA1_96_AES256;
		supported_session_etypes |= ENC_HMAC_SHA1_96_AES128;
	}
	if (force_rc4) {
		supported_session_etypes |= ENC_RC4_HMAC_MD5;
	}
	/*
	 * now that we remembered what to announce in pa_supported_enctypes
	 * and normalized ENC_HMAC_SHA1_96_AES256_SK, we restrict the
	 * rest to the enc types the local kdc supports.
	 */
	supported_enctypes &= kdc_enctypes;
	supported_session_etypes &= kdc_enctypes;

	status = dsdb_trust_parse_tdo_info(tmp_ctx, msg, &tdo);
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

	if (tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST) {
		/*
		 * We don't support WITHIN_FOREST yet
		 */
		krb5_clear_error_message(context);
		ret = SDB_ERR_NOENTRY;
		goto out;
	}

	if (tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_PIM_TRUST) {
		/*
		 * We don't support PIM_TRUST yet
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
	partner_realm = strupper_talloc(tmp_ctx, tdo->domain_name.string);
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

	ndr_err = ndr_pull_struct_blob(password_val, tmp_ctx, &password_blob,
				       (ndr_pull_flags_fn_t)ndr_pull_trustAuthInOutBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		krb5_clear_error_message(context);
		ret = EINVAL;
		goto out;
	}

	p = talloc_zero(tmp_ctx, struct samba_kdc_entry);
	if (!p) {
		ret = ENOMEM;
		goto out;
	}

	p->is_trust = true;
	p->kdc_db_ctx = kdc_db_ctx;
	p->realm_dn = realm_dn;
	p->supported_enctypes = pa_supported_enctypes;
	p->current_nttime = *kdc_db_ctx->current_nttime_ull;

	talloc_set_destructor(p, samba_kdc_entry_destructor);

	entry->skdc_entry = p;

	/* use 'whenCreated' */
	entry->created_by.time = ldb_msg_find_krb5time_ldap_time(msg, "whenCreated", 0);
	/* use 'kadmin' for now (needed by mit_samba) */
	ret = smb_krb5_make_principal(context,
				      &entry->created_by.principal,
				      realm, "kadmin", NULL);
	if (ret) {
		krb5_clear_error_message(context);
		goto out;
	}

	/*
	 * We always need to generate the canonicalized principal
	 * with the values of our database.
	 */
	ret = smb_krb5_make_principal(context, &entry->principal, realm,
				      "krbtgt", krbtgt_realm, NULL);
	if (ret) {
		krb5_clear_error_message(context);
		goto out;
	}
	smb_krb5_principal_set_type(context, entry->principal,
				    KRB5_NT_SRV_INST);

	entry->valid_start = NULL;

	/* we need to work out if we are going to use the current or
	 * the previous password hash.
	 * We base this on the kvno the client passes in. If the kvno
	 * passed in is equal to the current kvno in our database then
	 * we use the current structure. If it is the current kvno-1,
	 * then we use the previous substructure.
	 */

	/*
	 * Windows prefers the previous key for one hour.
	 */

	an_hour = INT64_C(1000) * 1000 * 10 * 3600;

	/*
	 * While a 'now' value of 0 is implausible, avoid this being a
	 * silly value in that case
	 */
	if (now > an_hour) {
		an_hour_ago = now - an_hour;
	} else {
		an_hour_ago = now;
	}

	/* first work out the current kvno */
	current_kvno = 0;
	for (i=0; i < password_blob.count; i++) {
		struct AuthenticationInformation *a =
			&password_blob.current.array[i];

		if (a->LastUpdateTime <= an_hour_ago) {
			prefer_current = true;
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
		if (prefer_current) {
			use_previous = false;
		} else if (previous_kvno < current_kvno) {
			use_previous = true;
		} else {
			use_previous = false;
		}

		if (flags & SDB_F_ADMIN_DATA) {
			/*
			 * let admin tool
			 * get to all keys
			 */
			use_previous = false;
			include_previous = true;
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

	current_keys = (struct samba_kdc_trust_keys) {
		.kvno = current_kvno,
		.supported_enctypes = supported_enctypes,
		.salt_principal = entry->principal,
		.auth_array = &password_blob.current,
	};

	previous_keys = (struct samba_kdc_trust_keys) {
		.kvno = previous_kvno,
		.supported_enctypes = supported_enctypes,
		.salt_principal = entry->principal,
		.auth_array = &password_blob.previous,
	};

	if (use_previous) {
		/*
		 * return the old keys as default keys
		 * with the requested kvno.
		 */
		previous_keys.skeys = &entry->keys;
		previous_keys.available_enctypes = &available_enctypes;
		previous_keys.returned_kvno = &returned_kvno;
	} else {
		/*
		 * return the current keys as default keys
		 * with the requested kvno.
		 */
		current_keys.skeys = &entry->keys;
		current_keys.available_enctypes = &available_enctypes;
		current_keys.returned_kvno = &returned_kvno;

		if (include_previous) {
			/*
			 * return the old keys in addition.
			 */
			previous_keys.skeys = &entry->old_keys;
		}
	}

	if (current_keys.skeys != NULL) {
		ret = samba_kdc_fill_trust_keys(context, &current_keys);
		if (ret != 0) {
			goto out;
		}
	}

	if (previous_keys.skeys != NULL) {
		ret = samba_kdc_fill_trust_keys(context, &previous_keys);
		if (ret != 0) {
			goto out;
		}
	}

	/* use the kvno the client specified, if available */
	if (flags & SDB_F_KVNO_SPECIFIED) {
		returned_kvno = kvno;
	}

	/* Must have found a cleartext or MD4 password */
	if (entry->keys.len == 0) {
		DBG_WARNING("no usable key found\n");
		krb5_clear_error_message(context);
		ret = SDB_ERR_NOENTRY;
		goto out;
	}

	entry->flags = (struct SDBFlags) {};
	entry->flags.immutable = 1;
	entry->flags.invalid = 0;
	entry->flags.server = 1;
	entry->flags.require_preauth = 1;

	entry->pw_end = NULL;

	entry->max_life = NULL;

	entry->max_renew = NULL;

	/* Match Windows behavior and allow forwardable flag in cross-realm. */
	entry->flags.forwardable = 1;

	entry->kvno = returned_kvno;

	/*
	 * We need to support all session keys enctypes for
	 * all keys we provide
	 */
	supported_session_etypes |= available_enctypes;

	ret = sdb_entry_set_etypes(entry);
	if (ret) {
		goto out;
	}

	{
		bool add_aes256 =
			supported_session_etypes & KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96;
		bool add_aes128 =
			supported_session_etypes & KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96;
		bool add_rc4 =
			supported_session_etypes & ENC_RC4_HMAC_MD5;
		ret = sdb_entry_set_session_etypes(entry,
						   add_aes256,
						   add_aes128,
						   add_rc4);
		if (ret) {
			goto out;
		}
	}

	p->msg = talloc_steal(p, msg);

	talloc_steal(kdc_db_ctx, p);

out:
	TALLOC_FREE(partner_realm);

	if (ret != 0) {
		/* This doesn't free ent itself, that is for the eventual caller to do */
		sdb_entry_free(entry);
	}

	talloc_free(tmp_ctx);
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
		krb5_set_error_message(context, ret, "samba_kdc_lookup_trust: out of memory");
		return ret;
	} else {
		int ret = EINVAL;
		krb5_set_error_message(context, ret, "samba_kdc_lookup_trust: %s", nt_errstr(status));
		return ret;
	}
}

static krb5_error_code samba_kdc_lookup_client(krb5_context context,
						struct samba_kdc_db_context *kdc_db_ctx,
						TALLOC_CTX *mem_ctx,
						krb5_const_principal principal,
						const char **attrs,
						const uint32_t dsdb_flags,
						struct ldb_dn **realm_dn,
						struct ldb_message **msg,
						unsigned sdb_flags)
{
	NTSTATUS nt_status;
	char *principal_string = NULL;

	if (smb_krb5_principal_get_type(context, principal) == KRB5_NT_ENTERPRISE_PRINCIPAL) {
		krb5_error_code ret = 0;

		ret = smb_krb5_principal_get_comp_string(mem_ctx, context,
							 principal, 0, &principal_string);
		if (ret) {
			return ret;
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
					      mem_ctx, principal_string, attrs, dsdb_flags,
					      realm_dn, msg);

	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_SUCH_USER)) {
		/* we will try again with a '$' appended */
		krb5_principal temp_principal = NULL;
		krb5_principal fallback_principal = NULL;
		unsigned int num_comp;
		char *fallback_realm = NULL;
		char *fallback_account = NULL;
		char *with_dollar = NULL;
		char *fallback_string = NULL;
		krb5_error_code ret;
		size_t len;

		ret = krb5_parse_name(context, principal_string,
				      &temp_principal);
		TALLOC_FREE(principal_string);
		if (ret != 0) {
			return ret;
		}

		num_comp = krb5_princ_size(context, temp_principal);
		if (num_comp != 1) {
			krb5_free_principal(context, temp_principal);
			return SDB_ERR_NOENTRY;
		}

		ret = smb_krb5_principal_get_comp_string(mem_ctx,
							 context, temp_principal, 0, &fallback_account);
		if (ret != 0) {
			krb5_free_principal(context, temp_principal);
			return ret;
		}

		if ((sdb_flags & SDB_F_GET_CLIENT) &&
		    (sdb_flags & SDB_F_FOR_AS_REQ) &&
		    ! (sdb_flags & SDB_F_CANON)) {
			/*
			 * The client has not requested canonicalisation,
			 * and the principal has not been found.
			 *
			 * At this point the only thing we are going
			 * to do is search for the account with a
			 * trailing '$', which we don't want to do if
			 * smb.conf has
			 *
			 *  kdc name match implicit dollar without canonicalization = no
			 *
			 * in which case we can just return early.
			 *
			 * Note, you might have expected a check
			 * against
			 *
			 *   sdb_flags & (SDB_F_CANON|SDB_F_FORCE_CANON)
			 *
			 * but that is incorrect here. The
			 * SDB_F_FORCE_CANON is telling us to
			 * canonicalise as we choose for the MIT kdc;
			 * that server will decide whether to use the
			 * canonicalized name or the original. All we
			 * are doing here is ruling out appending '$'
			 * as a matching strategy when the client has
			 * not requested canonicalization.
			 *
			 * If the MIT server wants to indicate the
			 * client has requested canonicalization, it
			 * sets the KRB5_KDB_FLAG_REFERRAL_OK flag,
			 * which we have converted into SDB_F_CANON
			 * (in mit_samba.c).
			 */
			bool implicit_dollar_fallback = \
				lpcfg_kdc_name_match_implicit_dollar_without_canonicalization(
					kdc_db_ctx->lp_ctx);
			if (! implicit_dollar_fallback) {
				DBG_ERR("NOT falling back to %s$\n",
					fallback_account);
				TALLOC_FREE(fallback_account);
				krb5_free_principal(context, temp_principal);
				return SDB_ERR_NOENTRY;
			}
		}

		len = strlen(fallback_account);
		if (len == 0 || fallback_account[len - 1] == '$') {
			/* there is already a $, so no fallback */
			TALLOC_FREE(fallback_account);
			krb5_free_principal(context, temp_principal);
			return SDB_ERR_NOENTRY;
		}

		fallback_realm = smb_krb5_principal_get_realm(
			mem_ctx, context, temp_principal);
		if (fallback_realm == NULL) {
			TALLOC_FREE(fallback_account);
			krb5_free_principal(context, temp_principal);
			return ENOMEM;
		}
		krb5_free_principal(context, temp_principal);
		temp_principal = NULL;

		with_dollar = talloc_asprintf(mem_ctx, "%s$",
					      fallback_account);
		TALLOC_FREE(fallback_account);
		if (with_dollar == NULL) {
			TALLOC_FREE(fallback_realm);
			return ENOMEM;
		}

		ret = smb_krb5_make_principal(context,
					      &fallback_principal,
					      fallback_realm,
					      with_dollar, NULL);
		TALLOC_FREE(with_dollar);
		TALLOC_FREE(fallback_realm);
		if (ret != 0) {
			return ret;
		}
		if (fallback_principal == NULL) {
			return ENOMEM;
		}

		ret = krb5_unparse_name(context,
					fallback_principal,
					&fallback_string);
		krb5_free_principal(context, fallback_principal);
		fallback_principal = NULL;
		if (ret != 0) {
			return ret;
		}

		nt_status = sam_get_results_principal(kdc_db_ctx->samdb,
						      mem_ctx,
						      fallback_string,
						      attrs, dsdb_flags,
						      realm_dn, msg);
		SAFE_FREE(fallback_string);
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

/* This is for the reset UF_SMARTCARD_REQUIRED password, but only in the expired case */
static void smartcard_random_pw_update(TALLOC_CTX *mem_ctx,
				       struct ldb_context *ldb,
				       struct ldb_dn *dn)
{
	int ret;
	NTSTATUS status = NT_STATUS_OK;
	/*
	 * The password_hash module expects these passwords to be
	 * null‐terminated, so we zero-initialise with {}
	 */
	uint8_t new_password[128] = {};
	DATA_BLOB password_blob = {.data = new_password,
				   .length = sizeof(new_password)};

	/*
	 * This will be re-randomised in password_hash, but want this
	 * to be random in a failure case
	 */
	generate_random_buffer(new_password, sizeof(new_password)-2);

	ret = ldb_transaction_start(ldb);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Transaction start for automated "
			"password rotation "
			"of soon-to-expire "
			"underlying password on account %s with "
			"UF_SMARTCARD_REQUIRED failed: %s\n",
			ldb_dn_get_linearized(dn),
			ldb_errstring(ldb));
		return;
	}

	status = samdb_set_password(ldb,
				    mem_ctx,
				    dn,
				    &password_blob,
				    NULL,
				    DSDB_PASSWORD_KDC_RESET_SMARTCARD_ACCOUNT_PASSWORD,
				    NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_transaction_cancel(ldb);
		DBG_ERR("Automated password rotation "
			"of soon-to-expire "
			"underlying password on account %s with "
			"UF_SMARTCARD_REQUIRED failed: %s\n",
			ldb_dn_get_linearized(dn),
			nt_errstr(status));
		return;
	}

	ret = ldb_transaction_commit(ldb);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Transaction commit for automated "
			"password rotation "
			"of soon-to-expire "
			"underlying password on account %s with "
			"UF_SMARTCARD_REQUIRED failed: %s\n",
			ldb_dn_get_linearized(dn),
			ldb_errstring(ldb));
	}
}

static krb5_error_code samba_kdc_fetch_client(krb5_context context,
					       struct samba_kdc_db_context *kdc_db_ctx,
					       TALLOC_CTX *mem_ctx,
					       krb5_const_principal principal,
					       unsigned flags,
					       krb5_kvno kvno,
					       struct sdb_entry *entry)
{
	struct ldb_dn *realm_dn;
	krb5_error_code ret;
	struct ldb_message *msg = NULL;
	int tries = 0;
	NTTIME pwd_last_set_last_loop = INT64_MAX;
	bool pwd_last_set_last_loop_set = false;

	/*
	 * We will try up to 3 times to rotate the expired or soon to
	 * expire password of a UF_SMARTCARD_REQUIRED account,
	 * re-starting the search if we attempted a password change
	 * (allowing the new secrets and expiry to be used).
	 *
	 * A failure to change the password is not fatal, as password
	 * changes are attempted before the ultimate expiry.  This way
	 * the server will still process an AS-REQ with PKINIT until
	 * it (later, in the KDC code) finds the password has actually
	 * expired.
	 */
	while (tries++ <= 2) {
		NTTIME pwd_last_set_this_loop;
		uint32_t attr_flags_computed;

		/*
		 * When we look up the client, we also pre-rotate any expired
		 * passwords in the UF_SMARTCARD_REQUIRED case
		 */
		ret = samba_kdc_lookup_client(context, kdc_db_ctx,
					      mem_ctx, principal, user_attrs, DSDB_SEARCH_UPDATE_MANAGED_PASSWORDS,
					      &realm_dn, &msg, flags);
		if (ret != 0) {
			return ret;
		}

		ret = samba_kdc_message2entry(context, kdc_db_ctx, mem_ctx,
					      principal, SAMBA_KDC_ENT_TYPE_CLIENT,
					      flags, kvno,
					      realm_dn, msg, entry);
		if (ret != 0) {
			return ret;
		}

		if (!(flags & SDB_F_FOR_AS_REQ)) {
			break;
		}

		/* This is the check on UF_SMARTCARD_REQUIRED */
		if (!(entry->flags.require_hwauth)) {
			break;
		}

		/*
		 * This check is also the configuration gate: the
		 * operational module will set a
		 * msDS-UserPasswordExpiryTimeComputed that in turn is
		 * represented here as NULL unless the
		 * expiry/auto-rotation of UF_SMARTCARD_REQUIRED
		 * accounts is enabled
		 */
		if (entry->pw_end == NULL) {
			break;
		}

		/*
		 * Find if the pwdLastSet has changed on an account
		 * that we are about to change the password for.  If
		 * we have both seen it and it has changed already, go
		 * with that, even if it would fail the tests.  As
		 * well as dealing with races, this will avoid a
		 * double-reset every loop if the TGT lifetime is
		 * longer than the expiry.
		 */
		pwd_last_set_this_loop =
			ldb_msg_find_attr_as_int64(msg, "pwdLastSet", INT64_MAX);
		if (pwd_last_set_last_loop_set &&
		    pwd_last_set_last_loop != pwd_last_set_this_loop) {
			break;
		}
		pwd_last_set_last_loop = pwd_last_set_this_loop;
		pwd_last_set_last_loop_set = true;

		attr_flags_computed
			= ldb_msg_find_attr_as_uint(msg,
						    "msDS-User-Account-Control-Computed",
						    UF_PASSWORD_EXPIRED /* A safe if chaotic default */);
		if (attr_flags_computed & UF_PASSWORD_EXPIRED) {
			/* Already expired, keep processing */
		} else {
			/*
			 * Will expire soon, but not already expired.
			 *
			 * However we must first
			 * check if this is before the TGT is due to
			 * expire.
			 *
			 * Then we check if we are half-way
			 * though the password lifetime before we make
			 * a password rotation.
			 */
			NTTIME must_change_time
				= samdb_result_nttime(msg,
						      "msDS-UserPasswordExpiryTimeComputed",
						      0);
			NTTIME pw_lifetime = must_change_time - pwd_last_set_this_loop;
			NTTIME pw_halflife = pw_lifetime / 2;
			if (must_change_time
			    > entry->skdc_entry->enforced_tgt_lifetime_nt_ticks + entry->skdc_entry->current_nttime) {
				/* Password will not expire before TGT will */
				break;
			}

			if (pwd_last_set_this_loop != 0
			    && pwd_last_set_this_loop + pw_halflife > entry->skdc_entry->current_nttime) {
				/*
				 * Still in first half of password
				 * lifetime, no change per
				 * https://lists.samba.org/archive/cifs-protocol/2024-May/004316.html
				 */
				break;
			}
			/* Keep processing */
		}

		if (kdc_db_ctx->rodc) {
			/*
			 * Nothing we can do locally on an RODC.  So
			 * we trigger pushing the user back to the
			 * full DC to ensure the PW is rotated.
			 */
			ret = SDB_ERR_NOT_FOUND_HERE;
			break;
		}

		/*
		 * Reset PW to random value.  All we can do is loop
		 * and hope we succeed again on failure, if we succeed
		 * then we will pass the tests above and break out of the loop
		 *
		 * We don't want to fail on error here as we might
		 * still be able to provide service to the client if
		 * the password is not yet actually expired.  They may get
		 * better luck at another KDC or at a later AS-REQ.
		 */
		smartcard_random_pw_update(mem_ctx, kdc_db_ctx->samdb, entry->skdc_entry->msg->dn);
	}

	return ret;

}

static krb5_error_code samba_kdc_fetch_krbtgt(krb5_context context,
					      struct samba_kdc_db_context *kdc_db_ctx,
					      TALLOC_CTX *mem_ctx,
					      krb5_const_principal principal,
					      unsigned flags,
					      uint32_t kvno,
					      struct sdb_entry *entry)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct loadparm_context *lp_ctx = kdc_db_ctx->lp_ctx;
	krb5_error_code ret = 0;
	int is_krbtgt;
	struct ldb_message *msg = NULL;
	struct ldb_dn *realm_dn = ldb_get_default_basedn(kdc_db_ctx->samdb);
	char *realm_from_princ;
	char *realm_princ_comp = NULL;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ENOMEM;
		goto out;
	}

	realm_from_princ = smb_krb5_principal_get_realm(
		tmp_ctx, context, principal);
	if (realm_from_princ == NULL) {
		/* can't happen */
		ret = SDB_ERR_NOENTRY;
		goto out;
	}

	is_krbtgt = smb_krb5_principal_is_tgs(context, principal);
	if (is_krbtgt == -1) {
		ret = ENOMEM;
		goto out;
	} else if (!is_krbtgt) {
		/* Not a krbtgt */
		ret = SDB_ERR_NOENTRY;
		goto out;
	}

	/* krbtgt case.  Either us or a trusted realm */

	ret = smb_krb5_principal_get_comp_string(tmp_ctx, context, principal, 1, &realm_princ_comp);
	if (ret == ENOENT) {
		/* OK. */
	} else if (ret) {
		goto out;
	}

	if (lpcfg_is_my_domain_or_realm(lp_ctx, realm_from_princ)
	    && (realm_princ_comp == NULL || lpcfg_is_my_domain_or_realm(lp_ctx, realm_princ_comp))) {
		/* us, or someone quite like us */
		/* Kludge, kludge, kludge.  If the realm part of krbtgt/realm,
 		 * is in our db, then direct the caller at our primary
 		 * krbtgt */

		int lret;
		unsigned int krbtgt_number;
		/* w2k8r2 sometimes gives us a kvno of 255 for inter-domain
		   trust tickets. We don't yet know what this means, but we do
		   seem to need to treat it as unspecified */
		if (flags & (SDB_F_KVNO_SPECIFIED|SDB_F_RODC_NUMBER_SPECIFIED)) {
			krbtgt_number = SAMBA_KVNO_GET_KRBTGT(kvno);
			if (kdc_db_ctx->rodc) {
				if (krbtgt_number != kdc_db_ctx->my_krbtgt_number) {
					ret = SDB_ERR_NOT_FOUND_HERE;
					goto out;
				}
			}
		} else {
			krbtgt_number = kdc_db_ctx->my_krbtgt_number;
		}

		if (krbtgt_number == kdc_db_ctx->my_krbtgt_number) {
			lret = dsdb_search_one(kdc_db_ctx->samdb, tmp_ctx,
					       &msg, kdc_db_ctx->krbtgt_dn, LDB_SCOPE_BASE,
					       krbtgt_attrs, DSDB_SEARCH_NO_GLOBAL_CATALOG | DSDB_SEARCH_UPDATE_MANAGED_PASSWORDS,
					       "(objectClass=user)");
		} else {
			/* We need to look up an RODC krbtgt (perhaps
			 * ours, if we are an RODC, perhaps another
			 * RODC if we are a read-write DC */
			lret = dsdb_search_one(kdc_db_ctx->samdb, tmp_ctx,
					       &msg, realm_dn, LDB_SCOPE_SUBTREE,
					       krbtgt_attrs,
					       DSDB_SEARCH_SHOW_EXTENDED_DN | DSDB_SEARCH_NO_GLOBAL_CATALOG | DSDB_SEARCH_UPDATE_MANAGED_PASSWORDS,
					       "(&(objectClass=user)(msDS-SecondaryKrbTgtNumber=%u))", (unsigned)(krbtgt_number));
		}

		if (lret == LDB_ERR_NO_SUCH_OBJECT) {
			krb5_warnx(context, "samba_kdc_fetch_krbtgt: could not find KRBTGT number %u in DB!",
				   (unsigned)(krbtgt_number));
			krb5_set_error_message(context, SDB_ERR_NOENTRY,
					       "samba_kdc_fetch_krbtgt: could not find KRBTGT number %u in DB!",
					       (unsigned)(krbtgt_number));
			ret = SDB_ERR_NOENTRY;
			goto out;
		} else if (lret != LDB_SUCCESS) {
			krb5_warnx(context, "samba_kdc_fetch_krbtgt: could not find KRBTGT number %u in DB!",
				   (unsigned)(krbtgt_number));
			krb5_set_error_message(context, SDB_ERR_NOENTRY,
					       "samba_kdc_fetch_krbtgt: could not find KRBTGT number %u in DB!",
					       (unsigned)(krbtgt_number));
			ret = SDB_ERR_NOENTRY;
			goto out;
		}

		ret = samba_kdc_message2entry(context, kdc_db_ctx, mem_ctx,
					      principal, SAMBA_KDC_ENT_TYPE_KRBTGT,
					      flags, kvno, realm_dn, msg, entry);
		if (ret != 0) {
			krb5_warnx(context, "samba_kdc_fetch_krbtgt: self krbtgt message2entry failed");
		}
	} else {
		enum trust_direction direction = UNKNOWN;
		const char *realm = NULL;

		/* Either an inbound or outbound trust */

		if (strcasecmp(lpcfg_realm(lp_ctx), realm_from_princ) == 0) {
			/* look for inbound trust */
			direction = INBOUND;
			realm = realm_princ_comp;
		} else {
			bool eq = false;

			ret = is_principal_component_equal_ignoring_case(context, principal, 1, lpcfg_realm(lp_ctx), &eq);
			if (ret) {
				goto out;
			}

			if (eq) {
				/* look for outbound trust */
				direction = OUTBOUND;
				realm = realm_from_princ;
			} else {
				krb5_warnx(context, "samba_kdc_fetch_krbtgt: not our realm for trusts ('%s', '%s')",
					   realm_from_princ,
					   realm_princ_comp);
				krb5_set_error_message(context, SDB_ERR_NOENTRY, "samba_kdc_fetch_krbtgt: not our realm for trusts ('%s', '%s')",
						       realm_from_princ,
						       realm_princ_comp);
				ret = SDB_ERR_NOENTRY;
				goto out;
			}
		}

		/* Trusted domains are under CN=system */

		ret = samba_kdc_lookup_trust(context, kdc_db_ctx->samdb,
				       tmp_ctx,
				       realm, realm_dn, &msg);

		if (ret != 0) {
			krb5_warnx(context, "samba_kdc_fetch_krbtgt: could not find principal in DB");
			krb5_set_error_message(context, ret, "samba_kdc_fetch_krbtgt: could not find principal in DB");
			goto out;
		}

		ret = samba_kdc_trust_message2entry(context, kdc_db_ctx, mem_ctx,
						    direction,
						    realm_dn, flags, kvno, msg, entry);
		if (ret != 0) {
			krb5_warnx(context, "samba_kdc_fetch_krbtgt: trust_message2entry failed for %s",
				   ldb_dn_get_linearized(msg->dn));
			krb5_set_error_message(context, ret, "samba_kdc_fetch_krbtgt: "
					       "trust_message2entry failed for %s",
					       ldb_dn_get_linearized(msg->dn));
		}
	}

out:
	talloc_free(tmp_ctx);
	return ret;
}

static krb5_error_code samba_kdc_lookup_server(krb5_context context,
					       struct samba_kdc_db_context *kdc_db_ctx,
					       TALLOC_CTX *mem_ctx,
					       krb5_const_principal principal,
					       unsigned flags,
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
					  server_attrs,
					  DSDB_SEARCH_SHOW_EXTENDED_DN | DSDB_SEARCH_NO_GLOBAL_CATALOG | DSDB_SEARCH_UPDATE_MANAGED_PASSWORDS,
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
					       mem_ctx, principal, server_attrs, DSDB_SEARCH_UPDATE_MANAGED_PASSWORDS,
					       realm_dn, msg, flags);
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
			ret = smb_krb5_principal_get_comp_string(mem_ctx, context, principal, 0, &str);
			if (ret) {
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
			krb5_set_error_message(context, ret, "samba_kdc_lookup_server: could not parse principal");
			krb5_warnx(context, "samba_kdc_lookup_server: could not parse principal");
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
				       server_attrs,
				       DSDB_SEARCH_SHOW_EXTENDED_DN | DSDB_SEARCH_NO_GLOBAL_CATALOG | DSDB_SEARCH_UPDATE_MANAGED_PASSWORDS,
				       "%s", filter);
		if (lret == LDB_ERR_NO_SUCH_OBJECT) {
			DBG_DEBUG("Failed to find an entry for %s filter:%s\n",
				  name1, filter);
			return SDB_ERR_NOENTRY;
		}
		if (lret == LDB_ERR_CONSTRAINT_VIOLATION) {
			DBG_DEBUG("Failed to find unique entry for %s filter:%s\n",
				  name1, filter);
			return SDB_ERR_NOENTRY;
		}
		if (lret != LDB_SUCCESS) {
			DBG_ERR("Failed single search for %s - %s\n",
				name1, ldb_errstring(kdc_db_ctx->samdb));
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
					      krb5_kvno kvno,
					      struct sdb_entry *entry)
{
	krb5_error_code ret;
	struct ldb_dn *realm_dn;
	struct ldb_message *msg;

	ret = samba_kdc_lookup_server(context, kdc_db_ctx, mem_ctx, principal,
				      flags, &realm_dn, &msg);
	if (ret != 0) {
		return ret;
	}

	ret = samba_kdc_message2entry(context, kdc_db_ctx, mem_ctx,
				      principal, SAMBA_KDC_ENT_TYPE_SERVER,
				      flags, kvno,
				      realm_dn, msg, entry);
	if (ret != 0) {
		char *client_name = NULL;
		krb5_error_code code;

		code = krb5_unparse_name(context, principal, &client_name);
		if (code == 0) {
			krb5_warnx(context,
				   "samba_kdc_fetch_server: message2entry failed for "
				   "%s",
				   client_name);
		} else {
			krb5_warnx(context,
				   "samba_kdc_fetch_server: message2entry and "
				   "krb5_unparse_name failed");
		}
		SAFE_FREE(client_name);
	}

	return ret;
}

static krb5_error_code samba_kdc_lookup_realm(krb5_context context,
					      struct samba_kdc_db_context *kdc_db_ctx,
					      krb5_const_principal principal,
					      unsigned flags,
					      struct sdb_entry *entry)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	krb5_error_code ret;
	bool check_realm = false;
	bool only_check_main_realm = false;
	const char *realm = NULL;
	struct dsdb_trust_routing_table *trt = NULL;
	const struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
	unsigned int num_comp;
	bool ok;
	char *upper = NULL;

	*entry = (struct sdb_entry) {};

	num_comp = krb5_princ_size(context, principal);

	if (flags & SDB_F_GET_CLIENT) {
		if (flags & SDB_F_FOR_AS_REQ) {
			check_realm = true;
		}
		if ((flags & SDB_F_FOR_TGS_REQ) &&
		    (flags & SDB_F_CROSS_REALM_PRINCIPAL))
		{
			/*
			 * The request is not for us...
			 * Let the caller ignore that
			 * the client is remote and
			 * has no local sdb_entry.
			 */
			TALLOC_FREE(frame);
			return SDB_ERR_NOT_FOUND_HERE;
		}
	}
	if (flags & SDB_F_GET_SERVER) {
		if (flags & SDB_F_FOR_TGS_REQ) {
			check_realm = true;
		}

		/* For S4U2Proxy the server has to be local */
		if (flags & SDB_F_S4U2PROXY_PRINCIPAL) {
			check_realm = true;
			only_check_main_realm = true;
		}
	}

	/*
	 * For S4U2Self the client has to be local
	 *
	 * Currently there's no server lookup,
	 * but make it strict in case it comes
	 * along in future.
	 */
	if (flags & SDB_F_S4U2SELF_PRINCIPAL) {
		check_realm = true;
		only_check_main_realm = true;
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

	if (only_check_main_realm) {
		/*
		 * The request is for us.
		 */
		TALLOC_FREE(frame);
		return 0;
	}

	if (smb_krb5_principal_get_type(context, principal) == KRB5_NT_ENTERPRISE_PRINCIPAL) {
		char *principal_string = NULL;
		krb5_principal enterprise_principal = NULL;
		char *enterprise_realm = NULL;

		if (num_comp != 1) {
			TALLOC_FREE(frame);
			return SDB_ERR_NOENTRY;
		}

		ret = smb_krb5_principal_get_comp_string(frame, context,
							 principal, 0, &principal_string);
		if (ret) {
			TALLOC_FREE(frame);
			return ret;
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
		bool is_krbtgt = false;

		ret = is_principal_component_equal(context, principal, 0, KRB5_TGS_NAME, &is_krbtgt);
		if (ret) {
			TALLOC_FREE(frame);
			return ret;
		}

		if (is_krbtgt) {
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
			char *service_realm = NULL;

			ret = smb_krb5_principal_get_comp_string(frame,
								 context,
								 principal,
								 num_comp - 1,
								 &service_realm);
			if (ret) {
				TALLOC_FREE(frame);
				return ret;
			} else {
				realm = service_realm;
			}
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

	ret = krb5_copy_principal(context, principal,
				  &entry->principal);
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
					   entry->principal,
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
				struct sdb_entry *entry)
{
	krb5_error_code ret = SDB_ERR_NOENTRY;
	TALLOC_CTX *mem_ctx = NULL;

	if ((flags & SDB_F_CANON) == 0 &&
	    (flags & SDB_F_FOR_AS_REQ) &&
	    (flags & SDB_F_GET_CLIENT)) {
		/*
		 * If smb.conf has
		 *
		 *    kdc require canonicalization = yes
		 *
		 * we refuse any AS REQ cname look-up if the client
		 * has not set the canonicalize flag.
		 *
		 * This will end up as KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN
		 * in the reply.
		 */
		bool require_canon = lpcfg_kdc_require_canonicalization(
			kdc_db_ctx->lp_ctx);
		if (require_canon) {
			return SDB_ERR_NOENTRY;
		}
	}

	mem_ctx = talloc_named(kdc_db_ctx, 0, "samba_kdc_fetch context");
	if (!mem_ctx) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "samba_kdc_fetch: talloc_named() failed!");
		return ret;
	}

	ret = samba_kdc_lookup_realm(context, kdc_db_ctx,
				     principal, flags, entry);
	if (ret != 0) {
		goto done;
	}

	ret = SDB_ERR_NOENTRY;

	if (flags & SDB_F_GET_CLIENT) {
		ret = samba_kdc_fetch_client(context, kdc_db_ctx, mem_ctx, principal, flags, kvno, entry);
		if (ret != SDB_ERR_NOENTRY) goto done;
	}
	if (flags & SDB_F_GET_SERVER) {
		/* krbtgt fits into this situation for trusted realms, and for resolving different versions of our own realm name */
		ret = samba_kdc_fetch_krbtgt(context, kdc_db_ctx, mem_ctx, principal, flags, kvno, entry);
		if (ret != SDB_ERR_NOENTRY) goto done;

		/* We return 'no entry' if it does not start with krbtgt/, so move to the common case quickly */
		ret = samba_kdc_fetch_server(context, kdc_db_ctx, mem_ctx, principal, flags, kvno, entry);
		if (ret != SDB_ERR_NOENTRY) goto done;
	}
	if (flags & SDB_F_GET_KRBTGT) {
		ret = samba_kdc_fetch_krbtgt(context, kdc_db_ctx, mem_ctx, principal, flags, kvno, entry);
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
	enum trust_direction trust_direction;
	unsigned int trust_index;
	unsigned int trust_count;
	struct ldb_message **trust_msgs;
	struct ldb_dn *realm_dn;
};

static krb5_error_code samba_kdc_seq(krb5_context context,
				     struct samba_kdc_db_context *kdc_db_ctx,
				     const unsigned sdb_flags,
				     struct sdb_entry *entry)
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
		goto out;
	}

	if (priv->index == priv->count) {
		goto trusts;
	}

	while (priv->index < priv->count) {
		msg = priv->msgs[priv->index++];

		sAMAccountName = ldb_msg_find_attr_as_string(msg, "sAMAccountName", NULL);
		if (sAMAccountName != NULL) {
			break;
		}
	}

	if (sAMAccountName == NULL) {
		/*
		 * This is not really possible,
		 * but instead returning
		 * SDB_ERR_NOENTRY, we
		 * go on with trusts
		 */
		goto trusts;
	}

	ret = smb_krb5_make_principal(context, &principal,
				      realm, sAMAccountName, NULL);
	if (ret != 0) {
		goto out;
	}

	ret = samba_kdc_message2entry(context, kdc_db_ctx, mem_ctx,
				      principal, SAMBA_KDC_ENT_TYPE_ANY,
				      sdb_flags|SDB_F_GET_ANY,
				      0 /* kvno */,
				      priv->realm_dn, msg, entry);
	krb5_free_principal(context, principal);

out:
	if (ret != 0) {
		TALLOC_FREE(priv);
		kdc_db_ctx->seq_ctx = NULL;
	} else {
		talloc_free(mem_ctx);
	}

	return ret;

trusts:
	while (priv->trust_index < priv->trust_count) {
		enum trust_direction trust_direction = priv->trust_direction;

		msg = priv->trust_msgs[priv->trust_index];

		if (trust_direction == INBOUND) {
			/*
			 * This time we try INBOUND keys,
			 * next time we'll do OUTBOUND
			 * for the same trust.
			 */
			priv->trust_direction = OUTBOUND;

			/*
			 * samba_kdc_trust_message2entry()
			 * will likely steal msg from us,
			 * so we need to make a copy for
			 * the first run with INBOUND,
			 * and let it steal without
			 * a copy in the OUTBOUND run.
			 */
			msg = ldb_msg_copy(priv->trust_msgs, msg);
			if (msg == NULL) {
				return ENOMEM;
			}
		} else {
			/*
			 * This time we try OUTBOUND keys,
			 * next time we'll do INBOUND for
			 * the next trust.
			 */
			priv->trust_direction = INBOUND;
			priv->trust_index++;
		}

		ret = samba_kdc_trust_message2entry(context,
						    kdc_db_ctx,
						    mem_ctx,
						    trust_direction,
						    priv->realm_dn,
						    sdb_flags|SDB_F_GET_ANY,
						    0, /* kvno */
						    msg,
						    entry);
		if (ret == SDB_ERR_NOENTRY) {
			continue;
		}
		goto out;
	}

	ret = SDB_ERR_NOENTRY;
	goto out;
}

krb5_error_code samba_kdc_firstkey(krb5_context context,
				   struct samba_kdc_db_context *kdc_db_ctx,
				   const unsigned sdb_flags,
				   struct sdb_entry *entry)
{
	struct ldb_context *ldb_ctx = kdc_db_ctx->samdb;
	struct samba_kdc_seq *priv = kdc_db_ctx->seq_ctx;
	char *realm;
	struct ldb_result *res = NULL;
	krb5_error_code ret;
	int lret;
	NTSTATUS status;

	if (priv) {
		TALLOC_FREE(priv);
		kdc_db_ctx->seq_ctx = NULL;
	}

	priv = talloc_zero(kdc_db_ctx, struct samba_kdc_seq);
	if (!priv) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "talloc: out of memory");
		return ret;
	}

	priv->realm_dn = ldb_get_default_basedn(ldb_ctx);

	ret = krb5_get_default_realm(context, &realm);
	if (ret != 0) {
		TALLOC_FREE(priv);
		return ret;
	}
	krb5_free_default_realm(context, realm);

	lret = dsdb_search(ldb_ctx, priv, &res,
			   priv->realm_dn, LDB_SCOPE_SUBTREE, user_attrs,
			   DSDB_SEARCH_NO_GLOBAL_CATALOG | DSDB_SEARCH_UPDATE_MANAGED_PASSWORDS,
			   "(objectClass=user)");

	if (lret != LDB_SUCCESS) {
		TALLOC_FREE(priv);
		return SDB_ERR_NOENTRY;
	}

	priv->count = res->count;
	priv->msgs = talloc_move(priv, &res->msgs);
	TALLOC_FREE(res);

	status = dsdb_trust_search_tdos(ldb_ctx,
					NULL, /* exclude */
					trust_attrs,
					priv,
					&res);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dsdb_trust_search_tdos() - %s\n",
			nt_errstr(status));
		TALLOC_FREE(priv);
		return SDB_ERR_NOENTRY;
	}

	priv->trust_direction = INBOUND;
	priv->trust_count = res->count;
	priv->trust_msgs = talloc_move(priv, &res->msgs);
	TALLOC_FREE(res);

	kdc_db_ctx->seq_ctx = priv;

	ret = samba_kdc_seq(context, kdc_db_ctx, sdb_flags, entry);

	if (ret != 0) {
		TALLOC_FREE(priv);
		kdc_db_ctx->seq_ctx = NULL;
	}
	return ret;
}

krb5_error_code samba_kdc_nextkey(krb5_context context,
				  struct samba_kdc_db_context *kdc_db_ctx,
				  const unsigned sdb_flags,
				  struct sdb_entry *entry)
{
	return samba_kdc_seq(context, kdc_db_ctx, sdb_flags, entry);
}

/* Check if a given entry may delegate or do s4u2self to this target principal
 *
 * The safest way to determine 'self' is to check the DB record made at
 * the time the principal was presented to the KDC.
 */
krb5_error_code
samba_kdc_check_client_matches_target_service(krb5_context context,
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
		return KRB5KRB_AP_ERR_BADMATCH;
	}

	talloc_free(frame);
	return 0;
}

/* Certificates printed by the Certificate Authority might have a
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
		krb5_set_error_message(context, ret, "samba_kdc_check_pkinit_ms_upn_match: talloc_named() failed!");
		return ret;
	}

	ret = samba_kdc_lookup_client(context, kdc_db_ctx,
				      mem_ctx, certificate_principal,
				      ms_upn_check_attrs, 0, &realm_dn, &msg,
				      SDB_F_CANON);

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
		talloc_free(mem_ctx);
		return ret;
	}

	el = ldb_msg_find_element(skdc_entry->msg, "msDS-AllowedToDelegateTo");
	if (el == NULL) {
		ret = ENOENT;
		goto bad_option;
	}
	SMB_ASSERT(el->num_values != 0);

	/*
	 * This is the Microsoft forwardable flag behavior.
	 *
	 * If the proxy (target) principal is NULL, and we have any authorized
	 * delegation target, allow to forward.
	 */
	if (target_principal == NULL) {
		talloc_free(mem_ctx);
		return 0;
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
				       " krb5_unparse_name_flags() failed!");
		return ret;
	}
	DBG_DEBUG("client[%s] for target[%s]\n",
		  client_dn, tmp);

	target_principal_name = talloc_strdup(mem_ctx, tmp);
	SAFE_FREE(tmp);
	if (target_principal_name == NULL) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret,
				       "samba_kdc_check_s4u2proxy:"
				       " talloc_strdup() failed!");
		talloc_free(mem_ctx);
		return ret;
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
		ret = ENOENT;
		goto bad_option;
	}

	DBG_DEBUG("client[%s] allowed target[%s]\n",
		  client_dn, target_principal_name);
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
	struct ldb_message *msg = NULL;
	struct samba_kdc_db_context *kdc_db_ctx = NULL;
	bool time_ok;

	/* The idea here is very simple.  Using Kerberos to
	 * authenticate the KDC to the LDAP server is highly likely to
	 * be circular.
	 *
	 * In future we may set this up to use EXTERNAL and SSL
	 * certificates, for now it will almost certainly be NTLMSSP_SET_USERNAME
	*/

	kdc_db_ctx = talloc_zero(mem_ctx, struct samba_kdc_db_context);
	if (kdc_db_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	kdc_db_ctx->ev_ctx = base_ctx->ev_ctx;
	kdc_db_ctx->lp_ctx = base_ctx->lp_ctx;
	kdc_db_ctx->msg_ctx = base_ctx->msg_ctx;

	/* Copy over the pointer that will be updated with the time */
	kdc_db_ctx->current_nttime_ull = base_ctx->current_nttime_ull;

	/* get default kdc policy */
	lpcfg_default_kdc_policy(mem_ctx,
				 base_ctx->lp_ctx,
				 &kdc_db_ctx->policy.svc_tkt_lifetime,
				 &kdc_db_ctx->policy.usr_tkt_lifetime,
				 &kdc_db_ctx->policy.renewal_lifetime);

	/* This is to allow "samba-tool domain exportkeytab to take a -H */
	if (base_ctx->samdb != NULL) {
		/*
		 * Caller is responsible for lifetimes.  In reality
		 * the whole thing is destroyed before leaving the
		 * function the samdb was passed into.
		 *
		 * We assume this DB is created from python and so
		 * can't be in the ldb_wrap cache.
		 */
		kdc_db_ctx->samdb = base_ctx->samdb;
	} else {
		struct auth_session_info *session_info = NULL;
		session_info = system_session(kdc_db_ctx->lp_ctx);
		if (session_info == NULL) {
			talloc_free(kdc_db_ctx);
			return NT_STATUS_INTERNAL_ERROR;
		}

		/* Setup the link to LDB */
		kdc_db_ctx->samdb = samdb_connect(kdc_db_ctx,
						  base_ctx->ev_ctx,
						  base_ctx->lp_ctx,
						  session_info,
						  NULL,
						  SAMBA_LDB_WRAP_CONNECT_FLAG_NO_SHARE_CONTEXT);
		if (kdc_db_ctx->samdb == NULL) {
			DBG_WARNING("Cannot open samdb for KDC backend!\n");
			talloc_free(kdc_db_ctx);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
	}

	/*
	 * Set the current time pointer, which will be updated before
	 * each packet (Heimdal) or fetch call (MIT)
	 */
	time_ok = dsdb_gmsa_set_current_time(kdc_db_ctx->samdb, kdc_db_ctx->current_nttime_ull);
	if (!time_ok) {
		talloc_free(kdc_db_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* Find out our own krbtgt kvno */
	ldb_ret = samdb_rodc(kdc_db_ctx->samdb, &kdc_db_ctx->rodc);
	if (ldb_ret != LDB_SUCCESS) {
		DBG_WARNING("Cannot determine if we are an RODC in KDC backend: %s\n",
			    ldb_errstring(kdc_db_ctx->samdb));
		talloc_free(kdc_db_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}
	if (kdc_db_ctx->rodc) {
		int my_krbtgt_number;
		const char *secondary_keytab[] = { "msDS-SecondaryKrbTgtNumber", NULL };
		struct ldb_dn *account_dn = NULL;
		struct ldb_dn *server_dn = samdb_server_dn(kdc_db_ctx->samdb, kdc_db_ctx);
		if (!server_dn) {
			DBG_WARNING("Cannot determine server DN in KDC backend: %s\n",
				    ldb_errstring(kdc_db_ctx->samdb));
			talloc_free(kdc_db_ctx);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}

		ldb_ret = samdb_reference_dn(kdc_db_ctx->samdb, kdc_db_ctx, server_dn,
					     "serverReference", &account_dn);
		if (ldb_ret != LDB_SUCCESS) {
			DBG_WARNING("Cannot determine server account in KDC backend: %s\n",
				    ldb_errstring(kdc_db_ctx->samdb));
			talloc_free(kdc_db_ctx);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}

		ldb_ret = samdb_reference_dn(kdc_db_ctx->samdb, kdc_db_ctx, account_dn,
					     "msDS-KrbTgtLink", &kdc_db_ctx->krbtgt_dn);
		talloc_free(account_dn);
		if (ldb_ret != LDB_SUCCESS) {
			DBG_WARNING("Cannot determine RODC krbtgt account in KDC backend: %s\n",
				    ldb_errstring(kdc_db_ctx->samdb));
			talloc_free(kdc_db_ctx);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}

		ldb_ret = dsdb_search_one(kdc_db_ctx->samdb, kdc_db_ctx,
					  &msg, kdc_db_ctx->krbtgt_dn, LDB_SCOPE_BASE,
					  secondary_keytab,
					  DSDB_SEARCH_NO_GLOBAL_CATALOG,
					  "(&(objectClass=user)(msDS-SecondaryKrbTgtNumber=*))");
		if (ldb_ret != LDB_SUCCESS) {
			DBG_WARNING("Cannot read krbtgt account %s in KDC backend to get msDS-SecondaryKrbTgtNumber: %s: %s\n",
				    ldb_dn_get_linearized(kdc_db_ctx->krbtgt_dn),
				    ldb_errstring(kdc_db_ctx->samdb),
				    ldb_strerror(ldb_ret));
			talloc_free(kdc_db_ctx);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
		my_krbtgt_number = ldb_msg_find_attr_as_int(msg, "msDS-SecondaryKrbTgtNumber", -1);
		if (my_krbtgt_number == -1) {
			DBG_WARNING("Cannot read msDS-SecondaryKrbTgtNumber from krbtgt account %s in KDC backend: got %d\n",
				    ldb_dn_get_linearized(kdc_db_ctx->krbtgt_dn),
				    my_krbtgt_number);
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
					  DSDB_SEARCH_NO_GLOBAL_CATALOG | DSDB_SEARCH_UPDATE_MANAGED_PASSWORDS,
					  "(&(objectClass=user)(samAccountName=krbtgt))");

		if (ldb_ret != LDB_SUCCESS) {
			DBG_WARNING("could not find own KRBTGT in DB: %s\n", ldb_errstring(kdc_db_ctx->samdb));
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

krb5_error_code dsdb_extract_aes_256_key(krb5_context context,
					 TALLOC_CTX *mem_ctx,
					 struct ldb_context *ldb,
					 const struct ldb_message *msg,
					 uint32_t user_account_control,
					 const uint32_t *kvno,
					 uint32_t *kvno_out,
					 DATA_BLOB *aes_256_key,
					 DATA_BLOB *salt)
{
	krb5_error_code krb5_ret;
	uint32_t supported_enctypes;
	unsigned flags = SDB_F_GET_CLIENT;
	struct sdb_entry sentry = {};

	if (kvno != NULL) {
		flags |= SDB_F_KVNO_SPECIFIED;
	}

	krb5_ret = samba_kdc_message2entry_keys(context,
						mem_ctx,
						ldb,
						msg,
						false, /* is_krbtgt */
						false, /* is_rodc */
						user_account_control,
						SAMBA_KDC_ENT_TYPE_CLIENT,
						flags,
						(kvno != NULL) ? *kvno : 0,
						&sentry,
						ENC_HMAC_SHA1_96_AES256,
						&supported_enctypes);
	if (krb5_ret != 0) {
		const char *krb5_err = krb5_get_error_message(context, krb5_ret);

		DBG_ERR("Failed to parse supplementalCredentials "
			"of %s with %s kvno using "
			"ENCTYPE_HMAC_SHA1_96_AES256 "
			"Kerberos Key: %s\n",
			ldb_dn_get_linearized(msg->dn),
			(kvno != NULL) ? "previous" : "current",
			krb5_err != NULL ? krb5_err : "<unknown>");

		krb5_free_error_message(context, krb5_err);

		return krb5_ret;
	}

	if ((supported_enctypes & ENC_HMAC_SHA1_96_AES256) == 0 ||
	    sentry.keys.len != 1) {
		DBG_INFO("Failed to find a ENCTYPE_HMAC_SHA1_96_AES256 "
			 "key in supplementalCredentials "
			 "of %s at KVNO %u (got %u keys, expected 1)\n",
			 ldb_dn_get_linearized(msg->dn),
			 sentry.kvno,
			 sentry.keys.len);
		sdb_entry_free(&sentry);
		return ENOENT;
	}

	if (sentry.keys.val[0].salt == NULL) {
		DBG_INFO("Failed to find a salt in "
			 "supplementalCredentials "
			 "of %s at KVNO %u\n",
			 ldb_dn_get_linearized(msg->dn),
			 sentry.kvno);
		sdb_entry_free(&sentry);
		return ENOENT;
	}

	if (aes_256_key != NULL) {
		*aes_256_key = data_blob_talloc_s(
			mem_ctx,
			KRB5_KEY_DATA(&sentry.keys.val[0].key),
			KRB5_KEY_LENGTH(&sentry.keys.val[0].key));
		if (aes_256_key->data == NULL) {
			sdb_entry_free(&sentry);
			return ENOMEM;
		}
	}

	if (salt != NULL) {
		*salt = data_blob_talloc(mem_ctx,
					 sentry.keys.val[0].salt->salt.data,
					 sentry.keys.val[0].salt->salt.length);
		if (salt->data == NULL) {
			sdb_entry_free(&sentry);
			return ENOMEM;
		}
	}

	if (kvno_out != NULL) {
		*kvno_out = sentry.kvno;
	}

	sdb_entry_free(&sentry);

	return 0;
}
