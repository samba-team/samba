/*
   Unix SMB/CIFS implementation.

   Copyright (C) Guenther Deschner <gd@samba.org> 2008
   Copyright (C) Michael Adam 2008

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
#include "smb_krb5.h"
#include "libnet/libnet_dssync.h"
#include "libnet/libnet_keytab.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "lib/crypto/md4.h"

#if defined(HAVE_ADS)

static NTSTATUS keytab_startup(struct dssync_context *ctx, TALLOC_CTX *mem_ctx,
			       struct replUpToDateVectorBlob **pold_utdv)
{
	krb5_error_code ret = 0;
	struct libnet_keytab_context *keytab_ctx;
	struct libnet_keytab_entry *entry;
	struct replUpToDateVectorBlob *old_utdv = NULL;
	char *principal;

	ret = libnet_keytab_init(mem_ctx, ctx->output_filename, &keytab_ctx);
	if (ret) {
		return krb5_to_nt_status(ret);
	}

	keytab_ctx->dns_domain_name = ctx->dns_domain_name;
	keytab_ctx->clean_old_entries = ctx->clean_old_entries;
	ctx->private_data = keytab_ctx;

	principal = talloc_asprintf(mem_ctx, "UTDV/%s@%s",
				    ctx->nc_dn, ctx->dns_domain_name);
	NT_STATUS_HAVE_NO_MEMORY(principal);

	entry = libnet_keytab_search(keytab_ctx, principal, 0, ENCTYPE_NULL,
				     mem_ctx);
	if (entry) {
		enum ndr_err_code ndr_err;
		old_utdv = talloc(mem_ctx, struct replUpToDateVectorBlob);

		ndr_err = ndr_pull_struct_blob(&entry->password, old_utdv, old_utdv,
				(ndr_pull_flags_fn_t)ndr_pull_replUpToDateVectorBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
			ctx->error_message = talloc_asprintf(ctx,
					"Failed to pull UpToDateVector: %s",
					nt_errstr(status));
			return status;
		}

		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_DEBUG(replUpToDateVectorBlob, old_utdv);
		}
	}

	if (pold_utdv) {
		*pold_utdv = old_utdv;
	}

	return NT_STATUS_OK;
}

static NTSTATUS keytab_finish(struct dssync_context *ctx, TALLOC_CTX *mem_ctx,
			      struct replUpToDateVectorBlob *new_utdv)
{
	NTSTATUS status = NT_STATUS_OK;
	krb5_error_code ret = 0;
	struct libnet_keytab_context *keytab_ctx =
		(struct libnet_keytab_context *)ctx->private_data;

	if (new_utdv) {
		enum ndr_err_code ndr_err;
		DATA_BLOB blob;

		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_DEBUG(replUpToDateVectorBlob, new_utdv);
		}

		ndr_err = ndr_push_struct_blob(&blob, mem_ctx, new_utdv,
				(ndr_push_flags_fn_t)ndr_push_replUpToDateVectorBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			status = ndr_map_error2ntstatus(ndr_err);
			ctx->error_message = talloc_asprintf(ctx,
					"Failed to push UpToDateVector: %s",
					nt_errstr(status));
			goto done;
		}

		status = libnet_keytab_add_to_keytab_entries(mem_ctx, keytab_ctx, 0,
							     ctx->nc_dn, "UTDV",
							     ENCTYPE_NULL,
							     blob);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	}

	ret = libnet_keytab_add(keytab_ctx);
	if (ret) {
		status = krb5_to_nt_status(ret);
		ctx->error_message = talloc_asprintf(ctx,
			"Failed to add entries to keytab %s: %s",
			keytab_ctx->keytab_name, error_message(ret));
		goto done;
	}

	ctx->result_message = talloc_asprintf(ctx,
		"Vampired %d accounts to keytab %s",
		keytab_ctx->count,
		keytab_ctx->keytab_name);

done:
	TALLOC_FREE(keytab_ctx);
	return status;
}

/****************************************************************
****************************************************************/

static  NTSTATUS parse_supplemental_credentials(TALLOC_CTX *mem_ctx,
			const DATA_BLOB *blob,
			struct package_PrimaryKerberosCtr3 **pkb3,
			struct package_PrimaryKerberosCtr4 **pkb4)
{
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	struct supplementalCredentialsBlob scb;
	struct supplementalCredentialsPackage *scpk = NULL;
	DATA_BLOB scpk_blob;
	struct package_PrimaryKerberosBlob *pkb;
	bool newer_keys = false;
	uint32_t j;

	ndr_err = ndr_pull_struct_blob_all(blob, mem_ctx, &scb,
			(ndr_pull_flags_fn_t)ndr_pull_supplementalCredentialsBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		goto done;
	}
	if ((scb.sub.signature != SUPPLEMENTAL_CREDENTIALS_SIGNATURE)
	    && (scb.sub.num_packages != 0))
	{
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_DEBUG(supplementalCredentialsBlob, &scb);
		}
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}
	for (j=0; j < scb.sub.num_packages; j++) {
		if (strcmp("Primary:Kerberos-Newer-Keys",
		    scb.sub.packages[j].name) == 0)
		{
			scpk = &scb.sub.packages[j];
			if (!scpk->data || !scpk->data[0]) {
				scpk = NULL;
				continue;
			}
			newer_keys = true;
			break;
		} else  if (strcmp("Primary:Kerberos",
				   scb.sub.packages[j].name) == 0)
		{
			/*
			 * grab this but don't break here:
			 * there might still be newer-keys ...
			 */
			scpk = &scb.sub.packages[j];
			if (!scpk->data || !scpk->data[0]) {
				scpk = NULL;
			}
		}
	}

	if (!scpk) {
		/* no data */
		status = NT_STATUS_OK;
		goto done;
	}

	scpk_blob = strhex_to_data_blob(mem_ctx, scpk->data);
	if (!scpk_blob.data) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	pkb = talloc_zero(mem_ctx, struct package_PrimaryKerberosBlob);
	if (!pkb) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	ndr_err = ndr_pull_struct_blob(&scpk_blob, mem_ctx, pkb,
			(ndr_pull_flags_fn_t)ndr_pull_package_PrimaryKerberosBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		goto done;
	}

	if (!newer_keys && pkb->version != 3) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	if (newer_keys && pkb->version != 4) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	if (pkb->version == 4 && pkb4) {
		*pkb4 = &pkb->ctr.ctr4;
	} else if (pkb->version == 3 && pkb3) {
		*pkb3 = &pkb->ctr.ctr3;
	}

	status = NT_STATUS_OK;

done:
	return status;
}

static NTSTATUS store_or_fetch_attribute(TALLOC_CTX *mem_ctx,
					 struct libnet_keytab_context *ctx,
					 const char *object_dn,
					 const char *attr,
					 char **value)
{
	DATA_BLOB blob = { .length = 0, };
	NTSTATUS status;

	if (*value == NULL) {
		/* look into keytab ... */
		struct libnet_keytab_entry *entry = NULL;
		char *principal = NULL;

		D_DEBUG("looking for %s/%s@%s in keytab...\n",
			attr, object_dn, ctx->dns_domain_name);

		principal = talloc_asprintf(mem_ctx,
					    "%s/%s@%s",
					    attr,
					    object_dn,
					    ctx->dns_domain_name);
		if (principal == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		entry = libnet_keytab_search(ctx,
					     principal,
					     0,
					     ENCTYPE_NULL,
					     mem_ctx);
		if (entry != NULL) {
			*value = talloc_strndup(mem_ctx,
						(char *)entry->password.data,
						entry->password.length);
			if (*value == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			D_DEBUG("found %s: %s\n", attr, *value);
			TALLOC_FREE(entry);
		} else {
			*value = NULL;
			D_DEBUG("entry not found\n");
		}
		TALLOC_FREE(principal);
		return NT_STATUS_OK;
	}

	blob = data_blob_string_const_null(*value);
	blob = data_blob_dup_talloc(mem_ctx, blob);
	if (blob.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = libnet_keytab_add_to_keytab_entries(mem_ctx,
						     ctx,
						     0,
						     object_dn,
						     attr,
						     ENCTYPE_NULL,
						     blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS parse_user(TALLOC_CTX *mem_ctx,
			   struct libnet_keytab_context *ctx,
			   struct drsuapi_DsReplicaObjectListItemEx *cur)
{
	NTSTATUS status = NT_STATUS_OK;
	uchar nt_passwd[16];
	DATA_BLOB *blob;
	int i = 0;
	struct drsuapi_DsReplicaAttribute *attr;
	bool got_pwd = false;

	struct package_PrimaryKerberosCtr3 *pkb3 = NULL;
	struct package_PrimaryKerberosCtr4 *pkb4 = NULL;

	char *object_dn = NULL;
	char *upn = NULL;
	char **spn = NULL;
	uint32_t num_spns = 0;
	char *name = NULL;
	uint32_t kvno = 0;
	uint32_t uacc = 0;
	uint32_t sam_type = 0;

	uint32_t pwd_history_len = 0;
	uint8_t *pwd_history = NULL;

	ZERO_STRUCT(nt_passwd);

	object_dn = talloc_strdup(mem_ctx, cur->object.identifier->dn);
	if (!object_dn) {
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(3, ("parsing user '%s'\n", object_dn));

	for (i=0; i < cur->object.attribute_ctr.num_attributes; i++) {

		attr = &cur->object.attribute_ctr.attributes[i];

		if (attr->attid == DRSUAPI_ATTID_servicePrincipalName) {
			uint32_t count;
			num_spns = attr->value_ctr.num_values;
			spn = talloc_array(mem_ctx, char *, num_spns);
			for (count = 0; count < num_spns; count++) {
				blob = attr->value_ctr.values[count].blob;
				if (blob == NULL) {
					continue;
				}
				pull_string_talloc(spn, NULL, 0,
						   &spn[count],
						   blob->data, blob->length,
						   STR_UNICODE);
			}
		}

		if (attr->attid == DRSUAPI_ATTID_unicodePwd &&
		    cur->meta_data_ctr != NULL &&
		    cur->meta_data_ctr->count ==
		    cur->object.attribute_ctr.num_attributes)
		{
			/*
			 * pick the kvno from the unicodePwd
			 * meta data, even without a unicodePwd blob
			 */
			kvno = cur->meta_data_ctr->meta_data[i].version;
		}

		if (attr->value_ctr.num_values != 1) {
			continue;
		}

		if (!attr->value_ctr.values[0].blob) {
			continue;
		}

		blob = attr->value_ctr.values[0].blob;

		switch (attr->attid) {
			case DRSUAPI_ATTID_unicodePwd:

				if (blob->length != 16) {
					break;
				}

				memcpy(&nt_passwd, blob->data, 16);
				got_pwd = true;
				break;
			case DRSUAPI_ATTID_ntPwdHistory:
				pwd_history_len = blob->length / 16;
				pwd_history = blob->data;
				break;
			case DRSUAPI_ATTID_userPrincipalName:
				pull_string_talloc(mem_ctx, NULL, 0, &upn,
						   blob->data, blob->length,
						   STR_UNICODE);
				break;
			case DRSUAPI_ATTID_sAMAccountName:
				pull_string_talloc(mem_ctx, NULL, 0, &name,
						   blob->data, blob->length,
						   STR_UNICODE);
				break;
			case DRSUAPI_ATTID_sAMAccountType:
				sam_type = IVAL(blob->data, 0);
				break;
			case DRSUAPI_ATTID_userAccountControl:
				uacc = IVAL(blob->data, 0);
				break;
			case DRSUAPI_ATTID_supplementalCredentials:
				status = parse_supplemental_credentials(mem_ctx,
									blob,
									&pkb3,
									&pkb4);
				if (!NT_STATUS_IS_OK(status)) {
					DEBUG(2, ("parsing of supplemental "
						  "credentials failed: %s\n",
						  nt_errstr(status)));
				}
				break;
			default:
				break;
		}
	}

	status = store_or_fetch_attribute(mem_ctx,
					  ctx,
					  object_dn,
					  "sAMAccountName",
					  &name);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("store_or_fetch_attribute(%s, %s, %s): %s\n",
			object_dn, "sAMAccountName", name,
			nt_errstr(status));
		return status;
	}

	if (!name) {
		DEBUG(10, ("no name (sAMAccountName) found - skipping.\n"));
		return NT_STATUS_OK;
	}

	DEBUG(1,("#%02d: %s:%d, ", ctx->count, name, kvno));
	DEBUGADD(1,("sAMAccountType: 0x%08x, userAccountControl: 0x%08x",
		sam_type, uacc));
	if (upn) {
		DEBUGADD(1,(", upn: %s", upn));
	}
	if (num_spns > 0) {
		DEBUGADD(1, (", spns: ["));
		for (i = 0; i < num_spns; i++) {
			DEBUGADD(1, ("%s%s", spn[i],
				     (i+1 == num_spns)?"]":", "));
		}
	}
	DEBUGADD(1,("\n"));

	if (got_pwd) {
		status = libnet_keytab_add_to_keytab_entries(mem_ctx, ctx, kvno, name, NULL,
							     ENCTYPE_ARCFOUR_HMAC,
							     data_blob_talloc(mem_ctx, nt_passwd, 16));

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	/* add kerberos keys (if any) */

	if (pkb4) {
		for (i=0; i < pkb4->num_keys; i++) {
			if (!pkb4->keys[i].value) {
				continue;
			}
			status = libnet_keytab_add_to_keytab_entries(mem_ctx, ctx, kvno,
								     name,
								     NULL,
								     pkb4->keys[i].keytype,
								     *pkb4->keys[i].value);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
		for (i=0; i < pkb4->num_old_keys; i++) {
			if (!pkb4->old_keys[i].value) {
				continue;
			}
			status = libnet_keytab_add_to_keytab_entries(mem_ctx, ctx, kvno - 1,
								     name,
								     NULL,
								     pkb4->old_keys[i].keytype,
								     *pkb4->old_keys[i].value);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
		for (i=0; i < pkb4->num_older_keys; i++) {
			if (!pkb4->older_keys[i].value) {
				continue;
			}
			status = libnet_keytab_add_to_keytab_entries(mem_ctx, ctx, kvno - 2,
								     name,
								     NULL,
								     pkb4->older_keys[i].keytype,
								     *pkb4->older_keys[i].value);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
	}

	if (pkb3) {
		for (i=0; i < pkb3->num_keys; i++) {
			if (!pkb3->keys[i].value) {
				continue;
			}
			status = libnet_keytab_add_to_keytab_entries(mem_ctx, ctx, kvno, name,
								     NULL,
								     pkb3->keys[i].keytype,
								     *pkb3->keys[i].value);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
		for (i=0; i < pkb3->num_old_keys; i++) {
			if (!pkb3->old_keys[i].value) {
				continue;
			}
			status = libnet_keytab_add_to_keytab_entries(mem_ctx, ctx, kvno - 1,
								     name,
								     NULL,
								     pkb3->old_keys[i].keytype,
								     *pkb3->old_keys[i].value);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
	}

	if (kvno < pwd_history_len) {
		return status;
	}

	/* add password history */

	/* skip first entry */
	if (got_pwd) {
		kvno--;
		i = 1;
	} else {
		i = 0;
	}

	for (; i<pwd_history_len; i++) {
		status = libnet_keytab_add_to_keytab_entries(mem_ctx, ctx, kvno--, name, NULL,
							     ENCTYPE_ARCFOUR_HMAC,
							     data_blob_talloc(mem_ctx, &pwd_history[i*16], 16));
		if (!NT_STATUS_IS_OK(status)) {
			break;
		}
	}

	return status;
}

static NTSTATUS parse_AuthenticationInformation(TALLOC_CTX *mem_ctx,
						struct libnet_keytab_context *ctx,
						const char *dn,
						const char *trust_name,
						const char *attr_name,
						const char *salt_principal,
						const char *type,
						uint32_t *kvno,
						const struct AuthenticationInformationArray *ia)
{
	uint32_t i;
	struct samr_Password _nthash = {{ 0, }};
	const struct samr_Password *nthash = NULL;
	const struct AuthInfoClear *clear = NULL;
	DATA_BLOB password_utf8 = data_blob_null;

	for (i = 0; i < ia->count; i++) {
		const struct AuthenticationInformation *a = &ia->array[i];

		switch (a->AuthType) {
		case TRUST_AUTH_TYPE_VERSION:
			*kvno = a->AuthInfo.version.version;
			break;
		case TRUST_AUTH_TYPE_NT4OWF:
			nthash = &a->AuthInfo.nt4owf.password;
			break;
		case TRUST_AUTH_TYPE_CLEAR:
			clear = &a->AuthInfo.clear;
			break;
		default:
			break;
		}
	}

	if (clear != NULL && clear->size != 0) {
		DATA_BLOB password_utf16 = data_blob_null;
		bool ok;

		password_utf16 = data_blob_const(clear->password,
						 clear->size);

		if (nthash == NULL) {
			mdfour(_nthash.hash,
			       password_utf16.data,
			       password_utf16.length);
			nthash = &_nthash;
		}

		ok = convert_string_talloc(mem_ctx,
					   CH_UTF16MUNGED, CH_UTF8,
					   password_utf16.data,
					   password_utf16.length,
					   (void *)&password_utf8.data,
					   &password_utf8.length);
		if (!ok) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (password_utf8.length != 0) {
		krb5_principal salt_princ = NULL;
		krb5_data salt = { 0, };
		krb5_data cleartext_data = { 0, };
		krb5_enctype enctypes[] = {
			ENCTYPE_AES256_CTS_HMAC_SHA1_96,
			ENCTYPE_AES128_CTS_HMAC_SHA1_96,
		};
		size_t ei;
		krb5_error_code kret;
		NTSTATUS status;

		kret = smb_krb5_parse_name(ctx->context,
					   salt_principal,
					   &salt_princ);
		if (kret != 0) {
			return NT_STATUS_NO_MEMORY;
		}

		cleartext_data.data = discard_const_p(char, password_utf8.data);
		cleartext_data.length = password_utf8.length;

		kret = smb_krb5_get_pw_salt(ctx->context,
					    salt_princ,
					    &salt);
		if (kret != 0) {
			krb5_free_principal(ctx->context, salt_princ);
			return NT_STATUS_NO_MEMORY;
		}

		for (ei = 0; ei < ARRAY_SIZE(enctypes); ei++) {
			krb5_keyblock keyb = { 0, };
			DATA_BLOB blob = data_blob_null;

			kret = smb_krb5_create_key_from_string(ctx->context,
							       salt_princ,
							       &salt,
							       &cleartext_data,
							       enctypes[ei],
							       &keyb);
			if (kret != 0) {
				smb_krb5_free_data_contents(ctx->context, &salt);
				krb5_free_principal(ctx->context, salt_princ);
				return NT_STATUS_NO_MEMORY;
			}

			blob = data_blob_talloc(mem_ctx,
						KRB5_KEY_DATA(&keyb),
						KRB5_KEY_LENGTH(&keyb));
			krb5_free_keyblock_contents(ctx->context, &keyb);

			status = libnet_keytab_add_to_keytab_entries(mem_ctx,
								     ctx,
								     *kvno,
								     trust_name,
								     attr_name,
								     enctypes[ei],
								     blob);
			if (!NT_STATUS_IS_OK(status)) {
				smb_krb5_free_data_contents(ctx->context, &salt);
				krb5_free_principal(ctx->context, salt_princ);
				return status;
			}
		}

		smb_krb5_free_data_contents(ctx->context, &salt);
		krb5_free_principal(ctx->context, salt_princ);
	}

	if (nthash != NULL) {
		DATA_BLOB blob = data_blob_null;
		NTSTATUS status;

		blob = data_blob_talloc(mem_ctx, nthash->hash, sizeof(nthash->hash));

		status = libnet_keytab_add_to_keytab_entries(mem_ctx, ctx,
							     *kvno,
							     trust_name,
							     attr_name,
							     ENCTYPE_ARCFOUR_HMAC,
							     blob);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS parse_trustAuthInOutBlob(TALLOC_CTX *mem_ctx,
					 struct libnet_keytab_context *ctx,
					 const char *dn,
					 const char *trust_name,
					 const char *attr_name,
					 const char *salt_principal,
					 const DATA_BLOB *blob)
{
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	struct trustAuthInOutBlob taiob;
	uint32_t kvno = 0;

	ndr_err = ndr_pull_struct_blob_all(blob, mem_ctx, &taiob,
			(ndr_pull_flags_fn_t)ndr_pull_trustAuthInOutBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		goto done;
	}

	D_WARNING("# %s %s/%s\n", dn, attr_name, trust_name);

	status = parse_AuthenticationInformation(mem_ctx,
						 ctx,
						 dn,
						 trust_name,
						 attr_name,
						 salt_principal,
						 "current",
						 &kvno,
						 &taiob.current);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("parsing of %s %s/current failed: %s\n",
			dn, attr_name, nt_errstr(status));
	}

	kvno -= 1;
	status = parse_AuthenticationInformation(mem_ctx,
						 ctx,
						 dn,
						 trust_name,
						 attr_name,
						 salt_principal,
						 "previous",
						 &kvno,
						 &taiob.previous);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("parsing of %s %s/previous failed: %s\n",
			dn, attr_name, nt_errstr(status));
	}

	status = NT_STATUS_OK;
done:
	return status;
}

static NTSTATUS parse_tdo(TALLOC_CTX *mem_ctx,
			  struct libnet_keytab_context *ctx,
			  struct drsuapi_DsReplicaObjectListItemEx *cur)
{
	uint32_t i;
	const char *dn = cur->object.identifier->dn;
	char *trustPartner = NULL;
	char *flatName = NULL;
	char *cn = NULL;
	char *trust_name = NULL;
	char *trust_realm = NULL;
	char *our_realm = NULL;
	const char *incoming_salt = NULL;
	const char *outgoing_salt = NULL;
	NTSTATUS status;

	D_NOTICE("parsing trust '%s'\n", dn);

	for (i = 0; i < cur->object.attribute_ctr.num_attributes; i++) {
		struct drsuapi_DsReplicaAttribute *attr =
			&cur->object.attribute_ctr.attributes[i];
		const DATA_BLOB *blob = NULL;

		if (attr->value_ctr.num_values != 1) {
			continue;
		}

		if (attr->value_ctr.values[0].blob == NULL) {
			continue;
		}

		blob = attr->value_ctr.values[0].blob;

		switch (attr->attid) {
		case DRSUAPI_ATTID_trustPartner:
			pull_string_talloc(mem_ctx, NULL, 0, &trustPartner,
					   blob->data, blob->length,
					   STR_UNICODE);
			break;
		case DRSUAPI_ATTID_flatName:
			pull_string_talloc(mem_ctx, NULL, 0, &flatName,
					   blob->data, blob->length,
					   STR_UNICODE);
			break;
		case DRSUAPI_ATTID_cn:
			pull_string_talloc(mem_ctx, NULL, 0, &cn,
					   blob->data, blob->length,
					   STR_UNICODE);
			break;
		default:
			break;
		}
	}

	if (trustPartner != NULL) {
		trust_name = trustPartner;
	} else if (flatName != NULL) {
		trust_name = flatName;
	} else {
		trust_name = cn;
	}

	status = store_or_fetch_attribute(mem_ctx,
					  ctx,
					  dn,
					  "REMOTETRUSTNAME",
					  &trust_name);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("store_or_fetch_attribute(%s, %s, %s): %s\n",
			dn, "REMOTETRUSTNAME", trust_name,
			nt_errstr(status));
		return status;
	}

	if (trust_name == NULL) {
		D_DEBUG("no trust_name (trustPartner, flatName, cn) found - "
			"skipping.\n");
		return NT_STATUS_OK;
	}

	trust_realm = strupper_talloc(mem_ctx, trust_name);
	if (trust_realm == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	our_realm = strupper_talloc(mem_ctx, ctx->dns_domain_name);
	if (our_realm == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	incoming_salt = talloc_asprintf(mem_ctx,
					"krbtgt/%s@%s",
					trust_realm,
					our_realm);
	if (incoming_salt == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	outgoing_salt = talloc_asprintf(mem_ctx,
					"krbtgt/%s@%s",
					our_realm,
					trust_realm);
	if (outgoing_salt == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < cur->object.attribute_ctr.num_attributes; i++) {
		struct drsuapi_DsReplicaAttribute *attr =
			&cur->object.attribute_ctr.attributes[i];
		const char *attr_name = NULL;
		const DATA_BLOB *blob = NULL;
		const char *salt_principal = NULL;

		if (attr->value_ctr.num_values != 1) {
			continue;
		}

		if (attr->value_ctr.values[0].blob == NULL) {
			continue;
		}

		blob = attr->value_ctr.values[0].blob;

		switch (attr->attid) {
		case DRSUAPI_ATTID_trustAuthIncoming:
			attr_name = "trustAuthIncoming";
			salt_principal = incoming_salt;
			break;
		case DRSUAPI_ATTID_trustAuthOutgoing:
			attr_name = "trustAuthOutgoing";
			salt_principal = outgoing_salt;
			break;
		default:
			break;
		}

		if (attr_name == NULL) {
			continue;
		}

		status = parse_trustAuthInOutBlob(mem_ctx,
						  ctx,
						  dn,
						  trust_name,
						  attr_name,
						  salt_principal,
						  blob);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("parsing of %s attr %s failed: %s\n",
				dn, attr_name, nt_errstr(status));
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS parse_object(TALLOC_CTX *mem_ctx,
			     struct libnet_keytab_context *ctx,
			     struct drsuapi_DsReplicaObjectListItemEx *cur)
{
	uint32_t i;

	if (cur->object.identifier->dn == NULL) {
		return NT_STATUS_OK;
	}

	for (i = 0; i < cur->object.attribute_ctr.num_attributes; i++) {
		struct drsuapi_DsReplicaAttribute *attr =
			&cur->object.attribute_ctr.attributes[i];
		const DATA_BLOB *blob = NULL;
		uint32_t val;

		switch (attr->attid) {
		case DRSUAPI_ATTID_isDeleted:
		case DRSUAPI_ATTID_isRecycled:
			break;
		default:
			continue;
		}

		if (attr->value_ctr.num_values != 1) {
			continue;
		}

		if (attr->value_ctr.values[0].blob == NULL) {
			continue;
		}

		blob = attr->value_ctr.values[0].blob;

		if (blob->length != 4) {
			continue;
		}

		val = PULL_LE_U32(blob->data, 0);
		if (val != 0) {
			/* ignore deleted object */
			return NT_STATUS_OK;
		}
	}

	for (i = 0; i < cur->object.attribute_ctr.num_attributes; i++) {
		struct drsuapi_DsReplicaAttribute *attr =
			&cur->object.attribute_ctr.attributes[i];

		switch (attr->attid) {
		case DRSUAPI_ATTID_unicodePwd:
		case DRSUAPI_ATTID_ntPwdHistory:
		case DRSUAPI_ATTID_supplementalCredentials:
			return parse_user(mem_ctx, ctx, cur);
		case DRSUAPI_ATTID_trustAuthIncoming:
		case DRSUAPI_ATTID_trustAuthOutgoing:
			return parse_tdo(mem_ctx, ctx, cur);
		default:
			continue;
		}
	}

	return NT_STATUS_OK;
}

static bool dn_is_in_object_list(struct dssync_context *ctx,
				 const char *dn)
{
	uint32_t count;

	if (ctx->object_count == 0) {
		return true;
	}

	for (count = 0; count < ctx->object_count; count++) {
		if (strequal(ctx->object_dns[count], dn)) {
			return true;
		}
	}

	return false;
}

/****************************************************************
****************************************************************/

static NTSTATUS keytab_process_objects(struct dssync_context *ctx,
				       TALLOC_CTX *mem_ctx,
				       struct drsuapi_DsReplicaObjectListItemEx *cur,
				       struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr)
{
	NTSTATUS status = NT_STATUS_OK;
	struct libnet_keytab_context *keytab_ctx =
		(struct libnet_keytab_context *)ctx->private_data;

	for (; cur; cur = cur->next_object) {
		/*
		 * When not in single object replication mode,
		 * the object_dn list is used as a positive write filter.
		 */
		if (!ctx->single_object_replication &&
		    !dn_is_in_object_list(ctx, cur->object.identifier->dn))
		{
			continue;
		}

		status = parse_object(mem_ctx, keytab_ctx, cur);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

 out:
	return status;
}

#else

static NTSTATUS keytab_startup(struct dssync_context *ctx, TALLOC_CTX *mem_ctx,
			       struct replUpToDateVectorBlob **pold_utdv)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS keytab_finish(struct dssync_context *ctx, TALLOC_CTX *mem_ctx,
			      struct replUpToDateVectorBlob *new_utdv)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS keytab_process_objects(struct dssync_context *ctx,
				       TALLOC_CTX *mem_ctx,
				       struct drsuapi_DsReplicaObjectListItemEx *cur,
				       struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr)
{
	return NT_STATUS_NOT_SUPPORTED;
}
#endif /* defined(HAVE_ADS) */

const struct dssync_ops libnet_dssync_keytab_ops = {
	.startup		= keytab_startup,
	.process_objects	= keytab_process_objects,
	.finish			= keytab_finish,
};
