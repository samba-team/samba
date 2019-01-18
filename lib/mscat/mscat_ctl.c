/*
 * Copyright (c) 2016      Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <string.h>
#include <stdint.h>

#include <util/debug.h>
#include <util/byteorder.h>
#include <util/data_blob.h>
#include <charset.h>

#include "mscat.h"
#include "mscat_private.h"

#define ASN1_NULL_DATA "\x05\x00"
#define ASN1_NULL_DATA_SIZE 2

#define HASH_SHA1_OBJID                "1.3.14.3.2.26"
#define HASH_SHA256_OBJID              "2.16.840.1.101.3.4.2.1"
#define HASH_SHA512_OBJID              "2.16.840.1.101.3.4.2.3"

#define SPC_INDIRECT_DATA_OBJID        "1.3.6.1.4.1.311.2.1.4"
#define SPC_PE_IMAGE_DATA_OBJID        "1.3.6.1.4.1.311.2.1.15"

#define CATALOG_LIST_OBJOID            "1.3.6.1.4.1.311.12.1.1"
#define CATALOG_LIST_MEMBER_OBJOID     "1.3.6.1.4.1.311.12.1.2"
#define CATALOG_LIST_MEMBER_V2_OBJOID  "1.3.6.1.4.1.311.12.1.3"

#define CAT_NAME_VALUE_OBJID           "1.3.6.1.4.1.311.12.2.1"
#define CAT_MEMBERINFO_OBJID           "1.3.6.1.4.1.311.12.2.2"

extern const asn1_static_node mscat_asn1_tab[];

struct mscat_ctl {
	int version;
	ASN1_TYPE asn1_desc;
	ASN1_TYPE tree_ctl;
	gnutls_datum_t raw_ctl;
};

static char *mscat_asn1_get_oid(TALLOC_CTX *mem_ctx,
				asn1_node root,
				const char *oid_name)
{
	char oid_str[32] = {0};
	int oid_len = sizeof(oid_str);
	int rc;

	rc = asn1_read_value(root,
			     oid_name,
			     oid_str,
			     &oid_len);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to read value '%s': %s\n",
			oid_name,
			asn1_strerror(rc));
		return NULL;
	}

	return talloc_strndup(mem_ctx, oid_str, oid_len);
}

static bool mscat_asn1_oid_equal(const char *o1, const char *o2)
{
	int cmp;

	cmp = strcmp(o1, o2);
	if (cmp != 0) {
		return false;
	}

	return true;
}

static int mscat_asn1_read_value(TALLOC_CTX *mem_ctx,
				 asn1_node root,
				 const char *name,
				 DATA_BLOB *blob)
{
	DATA_BLOB tmp = data_blob_null;
	unsigned int etype = ASN1_ETYPE_INVALID;
	int tmp_len = 0;
	size_t len;
	int rc;

	rc = asn1_read_value_type(root, name, NULL, &tmp_len, &etype);
	if (rc != ASN1_SUCCESS) {
		return rc;
	}
	len = tmp_len;

	if (etype == ASN1_ETYPE_BIT_STRING) {
		if (len + 7 < len) {
			return -1;
		}
		len = (len + 7) / 8;
	}

	if (len == 0) {
		*blob = data_blob_null;
		return 0;
	}

	if (len + 1 < len) {
		return -1;
	}
	tmp = data_blob_talloc_zero(mem_ctx, len + 1);
	if (tmp.data == NULL) {
		return -1;
	}

	rc = asn1_read_value(root,
			     name,
			     tmp.data,
			     &tmp_len);
	if (rc != ASN1_SUCCESS) {
		data_blob_free(&tmp);
		return rc;
	}
	len = tmp_len;

	if (etype == ASN1_ETYPE_BIT_STRING) {
		if (len + 7 < len) {
			return -1;
		}
		len = (len + 7) / 8;
	}
	tmp.length = len;

	*blob = tmp;

	return 0;
}

static int mscat_ctl_cleanup(struct mscat_ctl *ctl)
{
	if (ctl->asn1_desc != ASN1_TYPE_EMPTY) {
		asn1_delete_structure(&ctl->asn1_desc);
	}

	return 0;
}

struct mscat_ctl *mscat_ctl_init(TALLOC_CTX *mem_ctx)
{
	char error_string[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = {0};
	struct mscat_ctl *cat_ctl = NULL;
	int rc;

	cat_ctl = talloc_zero(mem_ctx, struct mscat_ctl);
	if (cat_ctl == NULL) {
		return NULL;
	}
	talloc_set_destructor(cat_ctl, mscat_ctl_cleanup);

	cat_ctl->asn1_desc = ASN1_TYPE_EMPTY;
	cat_ctl->tree_ctl = ASN1_TYPE_EMPTY;

	rc = asn1_array2tree(mscat_asn1_tab,
			     &cat_ctl->asn1_desc,
			     error_string);
	if (rc != ASN1_SUCCESS) {
		talloc_free(cat_ctl);
		DBG_ERR("Failed to create parser tree: %s - %s\n",
			asn1_strerror(rc),
			error_string);
		return NULL;
	}

	return cat_ctl;
}

int mscat_ctl_import(struct mscat_ctl *ctl,
		     struct mscat_pkcs7 *pkcs7)
{
	char error_string[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = {0};
	TALLOC_CTX *tmp_ctx = NULL;
	char *oid;
	bool ok;
	int rc;

	rc = gnutls_pkcs7_get_embedded_data(pkcs7->c,
					    GNUTLS_PKCS7_EDATA_GET_RAW,
					    &ctl->raw_ctl);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("Failed to get embedded data from pkcs7: %s\n",
			gnutls_strerror(rc));
		return -1;
	}

	rc = asn1_create_element(ctl->asn1_desc,
				 "CATALOG.CertTrustList",
				 &ctl->tree_ctl);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to create CertTrustList ASN.1 element - %s\n",
			asn1_strerror(rc));
		return -1;
	}

	rc = asn1_der_decoding(&ctl->tree_ctl,
			       ctl->raw_ctl.data,
			       ctl->raw_ctl.size,
			       error_string);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to parse ASN.1 CertTrustList: %s - %s\n",
			asn1_strerror(rc),
			error_string);
		return -1;
	}

	tmp_ctx = talloc_new(ctl);
	if (tmp_ctx == NULL) {
		return -1;
	}

	oid = mscat_asn1_get_oid(tmp_ctx,
				 ctl->tree_ctl,
				 "catalogListId.oid");
	if (oid == NULL) {
		rc = -1;
		goto done;
	}

	ok = mscat_asn1_oid_equal(oid, CATALOG_LIST_OBJOID);
	if (!ok) {
		DBG_ERR("Invalid oid (%s), expected CATALOG_LIST_OBJOID",
			oid);
		rc = -1;
		goto done;
	}
	talloc_free(oid);

	oid = mscat_asn1_get_oid(tmp_ctx,
				 ctl->tree_ctl,
				 "catalogListMemberId.oid");
	if (oid == NULL) {
		rc = -1;
		goto done;
	}

	ok = mscat_asn1_oid_equal(oid, CATALOG_LIST_MEMBER_V2_OBJOID);
	if (ok) {
		ctl->version = 2;
	} else {
		ok = mscat_asn1_oid_equal(oid, CATALOG_LIST_MEMBER_OBJOID);
		if (ok) {
			ctl->version = 1;
		} else {
			DBG_ERR("Invalid oid (%s), expected "
				"CATALOG_LIST_MEMBER_OBJOID",
				oid);
			rc = -1;
			goto done;
		}
	}

	rc = 0;
done:
	talloc_free(tmp_ctx);
	return rc;
}

static int ctl_get_member_checksum_string(struct mscat_ctl *ctl,
					  TALLOC_CTX *mem_ctx,
					  unsigned int idx,
					  const char **pchecksum,
					  size_t *pchecksum_size)
{
	TALLOC_CTX *tmp_ctx;
	DATA_BLOB chksum_ucs2 = data_blob_null;
	size_t converted_size = 0;
	char *checksum = NULL;
	char *element = NULL;
	int rc = -1;
	bool ok;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return -1;
	}

	element = talloc_asprintf(tmp_ctx,
				  "members.?%u.checksum",
				  idx);
	if (element == NULL) {
		goto done;
	}

	rc = mscat_asn1_read_value(tmp_ctx,
				   ctl->tree_ctl,
				   element,
				   &chksum_ucs2);
	talloc_free(element);
	if (rc != 0) {
		goto done;
	}

	ok = convert_string_talloc(mem_ctx,
				   CH_UTF16LE,
				   CH_UNIX,
				   chksum_ucs2.data,
				   chksum_ucs2.length,
				   (void **)&checksum,
				   &converted_size);
	if (!ok) {
		rc = -1;
		goto done;
	}

	*pchecksum_size = strlen(checksum) + 1;
	*pchecksum = talloc_move(mem_ctx, &checksum);

	rc = 0;
done:
	talloc_free(tmp_ctx);
	return rc;
}

static int ctl_get_member_checksum_blob(struct mscat_ctl *ctl,
					TALLOC_CTX *mem_ctx,
					unsigned int idx,
					uint8_t **pchecksum,
					size_t *pchecksum_size)
{
	TALLOC_CTX *tmp_ctx;
	DATA_BLOB chksum = data_blob_null;
	char *element = NULL;
	int rc = -1;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return -1;
	}

	element = talloc_asprintf(tmp_ctx,
				  "members.?%u.checksum",
				  idx);
	if (element == NULL) {
		goto done;
	}

	rc = mscat_asn1_read_value(tmp_ctx,
				   ctl->tree_ctl,
				   element,
				   &chksum);
	talloc_free(element);
	if (rc != 0) {
		goto done;
	}

	*pchecksum = talloc_move(mem_ctx, &chksum.data);
	*pchecksum_size = chksum.length;

	rc = 0;
done:
	talloc_free(tmp_ctx);
	return rc;
}

static int ctl_parse_name_value(struct mscat_ctl *ctl,
				TALLOC_CTX *mem_ctx,
				DATA_BLOB *content,
				char **pname,
				uint32_t *pflags,
				char **pvalue)
{
	char error_string[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = {0};
	ASN1_TYPE name_value = ASN1_TYPE_EMPTY;
	TALLOC_CTX *tmp_ctx;
	DATA_BLOB name_blob = data_blob_null;
	DATA_BLOB flags_blob = data_blob_null;
	DATA_BLOB value_blob = data_blob_null;
	size_t converted_size = 0;
	bool ok;
	int rc;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return -1;
	}

	rc = asn1_create_element(ctl->asn1_desc,
				 "CATALOG.CatalogNameValue",
				 &name_value);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to create element for "
			"CATALOG.CatalogNameValue: %s\n",
			asn1_strerror(rc));
		goto done;
	}

	rc = asn1_der_decoding(&name_value,
			       content->data,
			       content->length,
			       error_string);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to decode CATALOG.CatalogNameValue: %s - %s",
			asn1_strerror(rc),
			error_string);
		goto done;
	}

	rc = mscat_asn1_read_value(mem_ctx,
				   name_value,
				   "name",
				   &name_blob);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to read 'name': %s\n",
			asn1_strerror(rc));
		goto done;
	}

	rc = mscat_asn1_read_value(mem_ctx,
				   name_value,
				   "flags",
				   &flags_blob);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to read 'flags': %s\n",
			asn1_strerror(rc));
		goto done;
	}

	rc = mscat_asn1_read_value(mem_ctx,
				   name_value,
				   "value",
				   &value_blob);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to read 'value': %s\n",
			asn1_strerror(rc));
		goto done;
	}

	ok = convert_string_talloc(mem_ctx,
				   CH_UTF16BE,
				   CH_UNIX,
				   name_blob.data,
				   name_blob.length,
				   (void **)pname,
				   &converted_size);
	if (!ok) {
		rc = ASN1_MEM_ERROR;
		goto done;
	}

	*pflags = RIVAL(flags_blob.data, 0);

	ok = convert_string_talloc(mem_ctx,
				   CH_UTF16LE,
				   CH_UNIX,
				   value_blob.data,
				   value_blob.length,
				   (void **)pvalue,
				   &converted_size);
	if (!ok) {
		rc = ASN1_MEM_ERROR;
		goto done;
	}

	rc = 0;
done:
	talloc_free(tmp_ctx);
	return rc;
}

static int ctl_parse_member_info(struct mscat_ctl *ctl,
				 TALLOC_CTX *mem_ctx,
				 DATA_BLOB *content,
				 char **pname,
				 uint32_t *pid)
{
	char error_string[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = {0};
	ASN1_TYPE member_info = ASN1_TYPE_EMPTY;
	TALLOC_CTX *tmp_ctx;
	DATA_BLOB name_blob = data_blob_null;
	DATA_BLOB id_blob = data_blob_null;
	size_t converted_size = 0;
	bool ok;
	int rc;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return -1;
	}

	rc = asn1_create_element(ctl->asn1_desc,
				 "CATALOG.CatalogMemberInfo",
				 &member_info);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to create element for "
			"CATALOG.CatalogMemberInfo: %s\n",
			asn1_strerror(rc));
		goto done;
	}

	rc = asn1_der_decoding(&member_info,
			       content->data,
			       content->length,
			       error_string);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to decode CATALOG.CatalogMemberInfo: %s - %s",
			asn1_strerror(rc),
			error_string);
		goto done;
	}

	rc = mscat_asn1_read_value(mem_ctx,
				   member_info,
				   "name",
				   &name_blob);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to read 'name': %s\n",
			asn1_strerror(rc));
		goto done;
	}

	rc = mscat_asn1_read_value(mem_ctx,
				   member_info,
				   "id",
				   &id_blob);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to read 'id': %s\n",
			asn1_strerror(rc));
		goto done;
	}

	ok = convert_string_talloc(mem_ctx,
				   CH_UTF16BE,
				   CH_UNIX,
				   name_blob.data,
				   name_blob.length,
				   (void **)pname,
				   &converted_size);
	if (!ok) {
		rc = ASN1_MEM_ERROR;
		goto done;
	}

	*pid = RSVAL(id_blob.data, 0);

	rc = 0;
done:
	talloc_free(tmp_ctx);
	return rc;
}


static int ctl_spc_pe_image_data(struct mscat_ctl *ctl,
				 TALLOC_CTX *mem_ctx,
				 DATA_BLOB *content,
				 char **pfile)
{
	char error_string[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = {0};
	ASN1_TYPE spc_pe_image_data = ASN1_TYPE_EMPTY;
	DATA_BLOB flags_blob = data_blob_null;
	DATA_BLOB choice_blob = data_blob_null;
	char *file = NULL;
	TALLOC_CTX *tmp_ctx;
	int cmp;
	int rc;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return -1;
	}

	rc = asn1_create_element(ctl->asn1_desc,
				 "CATALOG.SpcPEImageData",
				 &spc_pe_image_data);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to create element for "
			"CATALOG.SpcPEImageData: %s\n",
			asn1_strerror(rc));
		goto done;
	}

	rc = asn1_der_decoding(&spc_pe_image_data,
			       content->data,
			       content->length,
			       error_string);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to decode CATALOG.SpcPEImageData: %s - %s",
			asn1_strerror(rc),
			error_string);
		goto done;
	}

	rc = mscat_asn1_read_value(tmp_ctx,
				   spc_pe_image_data,
				   "flags",
				   &flags_blob);
	if (rc == ASN1_SUCCESS) {
		uint32_t flags = RIVAL(flags_blob.data, 0);

		DBG_ERR(">>> SPC_PE_IMAGE_DATA FLAGS=0x%08x",
			flags);
	} else  {
		DBG_ERR("Failed to parse 'flags' in CATALOG.SpcPEImageData - %s",
			asn1_strerror(rc));
		goto done;
	}

	rc = mscat_asn1_read_value(tmp_ctx,
				   spc_pe_image_data,
				   "link",
				   &choice_blob);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to parse 'link' in CATALOG.SpcPEImageData - %s",
			asn1_strerror(rc));
		goto done;
	}

	cmp = strncmp((char *)choice_blob.data, "url", choice_blob.length);
	if (cmp == 0) {
		/* Never seen in a printer catalog file yet */
		DBG_INFO("Please report a Samba bug and attach the catalog "
			 "file\n");
	}

	cmp = strncmp((char *)choice_blob.data, "moniker", choice_blob.length);
	if (cmp == 0) {
		/* Never seen in a printer catalog file yet */
		DBG_INFO("Please report a Samba bug and attach the catalog "
			 "file\n");
	}

	cmp = strncmp((char *)choice_blob.data, "file", choice_blob.length);
	if (cmp == 0) {
		DATA_BLOB file_blob;
		char *link;

		rc = mscat_asn1_read_value(tmp_ctx,
					   spc_pe_image_data,
					   "link.file",
					   &choice_blob);
		if (rc != ASN1_SUCCESS) {
			goto done;
		}

		link = talloc_asprintf(tmp_ctx, "link.file.%s", (char *)choice_blob.data);
		if (link == NULL) {
			rc = -1;
			goto done;
		}

		rc = mscat_asn1_read_value(tmp_ctx,
					   spc_pe_image_data,
					   link,
					   &file_blob);
		if (rc != ASN1_SUCCESS) {
			DBG_ERR("Failed to read '%s' - %s",
				link,
				asn1_strerror(rc));
			rc = -1;
			goto done;
		}

		cmp = strncmp((char *)choice_blob.data, "unicode", choice_blob.length);
		if (cmp == 0) {
			size_t converted_size = 0;
			bool ok;

			ok = convert_string_talloc(tmp_ctx,
						   CH_UTF16BE,
						   CH_UNIX,
						   file_blob.data,
						   file_blob.length,
						   (void **)&file,
						   &converted_size);
			if (!ok) {
				rc = -1;
				goto done;
			}
		}

		cmp = strncmp((char *)choice_blob.data, "ascii", choice_blob.length);
		if (cmp == 0) {
			file = talloc_strndup(tmp_ctx,
					      (char *)file_blob.data,
					      file_blob.length);
			if (file == NULL) {
				rc = -1;
				goto done;
			}
		}
	}

	if (file != NULL) {
		*pfile = talloc_move(mem_ctx, &file);
	}

	rc = 0;
done:
	talloc_free(tmp_ctx);
	return rc;
}

static int ctl_spc_indirect_data(struct mscat_ctl *ctl,
				 TALLOC_CTX *mem_ctx,
				 DATA_BLOB *content,
				 enum mscat_mac_algorithm *pmac_algorithm,
				 uint8_t **pdigest,
				 size_t *pdigest_size)
{
	char error_string[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = {0};
	ASN1_TYPE spc_indirect_data = ASN1_TYPE_EMPTY;
	TALLOC_CTX *tmp_ctx;
	enum mscat_mac_algorithm mac_algorithm = MSCAT_MAC_UNKNOWN;
	const char *oid = NULL;
	DATA_BLOB data_value_blob = data_blob_null;
	DATA_BLOB digest_parameters_blob = data_blob_null;
	DATA_BLOB digest_blob = data_blob_null;
	bool ok;
	int rc;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return -1;
	}

	rc = asn1_create_element(ctl->asn1_desc,
				 "CATALOG.SpcIndirectData",
				 &spc_indirect_data);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to create element for "
			"CATALOG.SpcIndirectData: %s\n",
			asn1_strerror(rc));
		goto done;
	}

	rc = asn1_der_decoding(&spc_indirect_data,
			       content->data,
			       content->length,
			       error_string);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to decode CATALOG.SpcIndirectData: %s - %s",
			asn1_strerror(rc),
			error_string);
		goto done;
	}

	oid = mscat_asn1_get_oid(tmp_ctx,
				 spc_indirect_data,
				 "data.type");
	if (oid == NULL) {
		goto done;
	}

	rc = mscat_asn1_read_value(tmp_ctx,
				   spc_indirect_data,
				   "data.value",
				   &data_value_blob);
	if (rc != ASN1_SUCCESS) {
		DBG_ERR("Failed to find data.value in SpcIndirectData: %s\n",
			asn1_strerror(rc));
		goto done;
	}

	ok = mscat_asn1_oid_equal(oid, SPC_PE_IMAGE_DATA_OBJID);
	if (ok) {
		char *file = NULL;

		rc = ctl_spc_pe_image_data(ctl,
					   tmp_ctx,
					   &data_value_blob,
					   &file);
		if (rc != 0) {
			goto done;
		}

		/* Just returns <<<Obsolete>>> as file */
		DBG_NOTICE(">>> LINK: %s",
			   file);
	}

	oid = mscat_asn1_get_oid(tmp_ctx,
				 spc_indirect_data,
				 "messageDigest.digestAlgorithm.algorithm");
	if (oid == NULL) {
		goto done;
	}

	rc = mscat_asn1_read_value(tmp_ctx,
				   spc_indirect_data,
				   "messageDigest.digestAlgorithm.parameters",
				   &digest_parameters_blob);
	if (rc == ASN1_SUCCESS) {
		/* Make sure we don't have garbage */
		int cmp;

		if (digest_parameters_blob.length != ASN1_NULL_DATA_SIZE) {
			rc = -1;
			goto done;
		}
		cmp = memcmp(digest_parameters_blob.data,
			     ASN1_NULL_DATA,
			     digest_parameters_blob.length);
		if (cmp != 0) {
			rc = -1;
			goto done;
		}
	} else if (rc != ASN1_ELEMENT_NOT_FOUND) {
		DBG_ERR("Failed to read 'messageDigest.digestAlgorithm.parameters': %s\n",
			asn1_strerror(rc));
		goto done;
	}

	ok = mscat_asn1_oid_equal(oid, HASH_SHA1_OBJID);
	if (ok) {
		mac_algorithm = MSCAT_MAC_SHA1;
	}

	ok = mscat_asn1_oid_equal(oid, HASH_SHA256_OBJID);
	if (ok) {
		mac_algorithm = MSCAT_MAC_SHA256;
	}

	if (mac_algorithm != MSCAT_MAC_UNKNOWN &&
	    mac_algorithm != MSCAT_MAC_NULL) {
		rc = mscat_asn1_read_value(tmp_ctx,
					   spc_indirect_data,
					   "messageDigest.digest",
					   &digest_blob);
		if (rc != ASN1_SUCCESS) {
			DBG_ERR("Failed to find messageDigest.digest in "
				"SpcIndirectData: %s\n",
				asn1_strerror(rc));
			goto done;
		}
	}

	*pmac_algorithm = mac_algorithm;
	*pdigest = talloc_move(mem_ctx, &digest_blob.data);
	*pdigest_size = digest_blob.length;

	rc = 0;
done:
	talloc_free(tmp_ctx);
	return rc;
}

static int ctl_get_member_attributes(struct mscat_ctl *ctl,
				     TALLOC_CTX *mem_ctx,
				     unsigned int idx,
				     struct mscat_ctl_member *m)
{
	TALLOC_CTX *tmp_ctx;
	char *el1 = NULL;
	int count = 0;
	int i;
	int rc = -1;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return -1;
	}

	el1 = talloc_asprintf(tmp_ctx,
			      "members.?%u.attributes",
			      idx);
	if (el1 == NULL) {
		goto done;
	}

	rc = asn1_number_of_elements(ctl->tree_ctl,
				     el1,
				     &count);
	if (rc != ASN1_SUCCESS) {
		goto done;
	}

	for (i = 0; i < count; i++) {
		int content_start = 0;
		int content_end = 0;
		size_t content_len;
		DATA_BLOB content;
		char *el2;
		char *oid;
		bool ok;

		el2 = talloc_asprintf(tmp_ctx,
				      "%s.?%d.contentType",
				      el1,
				      i + 1);
		if (el2 == NULL) {
			rc = -1;
			goto done;
		}

		oid = mscat_asn1_get_oid(tmp_ctx,
					 ctl->tree_ctl,
					 el2);
		talloc_free(el2);
		if (oid == NULL) {
			rc = -1;
			goto done;
		}

		/* FIXME Looks like this is always 1 */
		el2 = talloc_asprintf(tmp_ctx,
				      "%s.?%d.content.?1",
				      el1,
				      i + 1);
		if (el2 == NULL) {
			rc = -1;
			goto done;
		}

		DBG_DEBUG("Decode element (startEnd)  %s",
			  el2);

		rc = asn1_der_decoding_startEnd(ctl->tree_ctl,
						ctl->raw_ctl.data,
						ctl->raw_ctl.size,
						el2,
						&content_start,
						&content_end);
		if (rc != ASN1_SUCCESS) {
			goto done;
		}
		if (content_start < content_end) {
			goto done;
		}
		content_len = content_end - content_start + 1;

		DBG_DEBUG("Content data_blob length: %zu",
			  content_len);

		content = data_blob_talloc_zero(tmp_ctx, content_len);
		if (content.data == NULL) {
			rc = -1;
			goto done;
		}
		memcpy(content.data,
		       &ctl->raw_ctl.data[content_start],
		       content_len);

		ok = mscat_asn1_oid_equal(oid, CAT_NAME_VALUE_OBJID);
		if (ok) {
			char *name;
			uint32_t flags;
			char *value;
			int cmp;

			rc = ctl_parse_name_value(ctl,
						  tmp_ctx,
						  &content,
						  &name,
						  &flags,
						  &value);
			if (rc != 0) {
				goto done;
			}

			DBG_DEBUG("Parsed NameValue: name=%s, flags=%u, value=%s",
				  name,
				  flags,
				  value);

			cmp = strcmp(name, "File");
			if (cmp == 0) {
				m->file.name = talloc_move(m, &value);
				m->file.flags = flags;

				continue;
			}

			cmp = strcmp(name, "OSAttr");
			if (cmp == 0) {
				m->osattr.value = talloc_move(m, &value);
				m->osattr.flags = flags;

				continue;
			}
		}

		ok = mscat_asn1_oid_equal(oid, CAT_MEMBERINFO_OBJID);
		if (ok) {
			char *name;
			uint32_t id;

			rc = ctl_parse_member_info(ctl,
						   tmp_ctx,
						   &content,
						   &name,
						   &id);
			if (rc != 0) {
				goto done;
			}

			m->info.guid = talloc_move(m, &name);
			m->info.id = id;

			continue;
		}

		ok = mscat_asn1_oid_equal(oid, SPC_INDIRECT_DATA_OBJID);
		if (ok) {
			rc = ctl_spc_indirect_data(ctl,
						  m,
						  &content,
						  &m->mac.type,
						  &m->mac.digest,
						  &m->mac.digest_size);
			if (rc != 0) {
				goto done;
			}

			continue;
		}
	}

	rc = 0;
done:
	talloc_free(tmp_ctx);
	return rc;
}

int mscat_ctl_get_member(struct mscat_ctl *ctl,
			 TALLOC_CTX *mem_ctx,
			 unsigned int idx,
			 struct mscat_ctl_member **pmember)
{
	TALLOC_CTX *tmp_ctx;
	struct mscat_ctl_member *m = NULL;
	int rc = -1;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return -1;
	}

	m = talloc_zero(tmp_ctx, struct mscat_ctl_member);
	if (m == NULL) {
		rc = -1;
		goto done;
	}

	if (ctl->version == 1) {
		m->checksum.type = MSCAT_CHECKSUM_STRING;
		rc = ctl_get_member_checksum_string(ctl,
						    m,
						    idx,
						    &m->checksum.string,
						    &m->checksum.size);
	} else if (ctl->version == 2) {
		m->checksum.type = MSCAT_CHECKSUM_BLOB;
		rc = ctl_get_member_checksum_blob(ctl,
						  m,
						  idx,
						  &m->checksum.blob,
						  &m->checksum.size);
	}
	if (rc != 0) {
		goto done;
	}

	rc = ctl_get_member_attributes(ctl,
				       mem_ctx,
				       idx,
				       m);
	if (rc != 0) {
		goto done;
	}

	*pmember = talloc_move(mem_ctx, &m);

	rc = 0;
done:
	talloc_free(tmp_ctx);
	return rc;
}

int mscat_ctl_get_member_count(struct mscat_ctl *ctl)
{
	int count = 0;
	int rc;

	rc = asn1_number_of_elements(ctl->tree_ctl,
				     "members",
				     &count);
	if (rc != ASN1_SUCCESS) {
		return -1;
	}

	return count;
}

int mscat_ctl_get_attribute(struct mscat_ctl *ctl,
			    TALLOC_CTX *mem_ctx,
			    unsigned int idx,
			    struct mscat_ctl_attribute **pattribute)
{
	TALLOC_CTX *tmp_ctx;
	const char *el1 = NULL;
	const char *el2 = NULL;
	const char *oid = NULL;
	char *name = NULL;
	uint32_t flags = 0;
	char *value = NULL;
	struct mscat_ctl_attribute *a = NULL;
	DATA_BLOB encapsulated_data_blob = data_blob_null;
	int rc;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return -1;
	}

	a = talloc_zero(tmp_ctx, struct mscat_ctl_attribute);
	if (a == NULL) {
		rc = -1;
		goto done;
	}

	el1 = talloc_asprintf(tmp_ctx,
				  "attributes.?%u.dataId",
				  idx);
	if (el1 == NULL) {
		rc = -1;
		goto done;
	}

	oid = mscat_asn1_get_oid(tmp_ctx,
				 ctl->tree_ctl,
				 el1);
	if (oid == NULL) {
		rc = -1;
		goto done;
	}

	el2 = talloc_asprintf(tmp_ctx,
				  "attributes.?%u.encapsulated_data",
				  idx);
	if (el2 == NULL) {
		rc = -1;
		goto done;
	}

	rc = mscat_asn1_read_value(tmp_ctx,
				   ctl->tree_ctl,
				   el2,
				   &encapsulated_data_blob);
	if (rc != ASN1_SUCCESS) {
		goto done;
	}

	rc = ctl_parse_name_value(ctl,
				  tmp_ctx,
				  &encapsulated_data_blob,
				  &name,
				  &flags,
				  &value);
	if (rc != 0) {
		goto done;
	}

	a->name = talloc_move(a, &name);
	a->flags = flags;
	a->value = talloc_move(a, &value);

	*pattribute = talloc_move(mem_ctx, &a);

	rc = 0;
done:
	talloc_free(tmp_ctx);
	return rc;
}

int mscat_ctl_get_attribute_count(struct mscat_ctl *ctl)
{
	int count = 0;
	int rc;

	rc = asn1_number_of_elements(ctl->tree_ctl,
				     "attributes",
				     &count);
	if (rc != ASN1_SUCCESS) {
		return -1;
	}

	return count;
}
