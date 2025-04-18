/*
   Unix SMB/CIFS implementation.

   routines for printing some linked list structs in DRSUAPI

   Copyright (C) Stefan (metze) Metzmacher 2005
   Copyright (C) Matthieu Patou 2013

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
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "../lib/util/asn1.h"
#include "librpc/ndr/ndr_compression.h"
/* We don't need multibyte if we're just comparing to 'ff' */
#undef strncasecmp

void ndr_print_drsuapi_DsReplicaObjectListItem(struct ndr_print *ndr, const char *name,
					       const struct drsuapi_DsReplicaObjectListItem *r)
{
	ndr_print_struct(ndr, name, "drsuapi_DsReplicaObjectListItem");
	ndr->depth++;
	ndr_print_ptr(ndr, "next_object", r->next_object);
	ndr_print_drsuapi_DsReplicaObject(ndr, "object", &r->object);
	ndr->depth--;
	if (r->next_object) {
		ndr_print_drsuapi_DsReplicaObjectListItem(ndr, "next_object", r->next_object);
	}
}

void ndr_print_drsuapi_DsReplicaObjectListItemEx(struct ndr_print *ndr, const char *name, const struct drsuapi_DsReplicaObjectListItemEx *r)
{
	ndr_print_struct(ndr, name, "drsuapi_DsReplicaObjectListItemEx");
	ndr->depth++;
	ndr_print_ptr(ndr, "next_object", r->next_object);
	ndr_print_drsuapi_DsReplicaObject(ndr, "object", &r->object);
	ndr_print_uint32(ndr, "is_nc_prefix", r->is_nc_prefix);
	ndr_print_ptr(ndr, "parent_object_guid", r->parent_object_guid);
	ndr->depth++;
	if (r->parent_object_guid) {
		ndr_print_GUID(ndr, "parent_object_guid", r->parent_object_guid);
	}
	ndr->depth--;
	ndr_print_ptr(ndr, "meta_data_ctr", r->meta_data_ctr);
	ndr->depth++;
	if (r->meta_data_ctr) {
		ndr_print_drsuapi_DsReplicaMetaDataCtr(ndr, "meta_data_ctr", r->meta_data_ctr);
	}
	ndr->depth--;
	ndr->depth--;
	if (r->next_object) {
		ndr_print_drsuapi_DsReplicaObjectListItemEx(ndr, "next_object", r->next_object);
	}
}

_PUBLIC_ void ndr_print_drsuapi_DsReplicaOID(struct ndr_print *ndr, const char *name, const struct drsuapi_DsReplicaOID *r)
{
	ndr_print_struct(ndr, name, "drsuapi_DsReplicaOID");
	ndr->depth++;
	ndr_print_uint32(ndr, "length", r->length);
	ndr->print(ndr, "%-25s: length=%"PRIu32, "oid", r->length);
	if (r->binary_oid) {
		char *partial_oid = NULL;
		DATA_BLOB oid_blob = data_blob_const(r->binary_oid, r->length);
		char *hex_str = data_blob_hex_string_upper(ndr, &oid_blob);
		ber_read_partial_OID_String(ndr, oid_blob, &partial_oid);
		ndr->depth++;
		ndr->print(ndr, "%-25s: 0x%s (%s)", "binary_oid", hex_str, partial_oid);
		ndr->depth--;
		TALLOC_FREE(hex_str);
		TALLOC_FREE(partial_oid);
	}
	ndr->depth--;
}

static void _print_drsuapi_DsAttributeValue_attid(struct ndr_print *ndr, const char *name,
						  const struct drsuapi_DsAttributeValue *r)
{
	uint32_t v;

	ndr_print_struct(ndr, name, "drsuapi_DsAttributeValue");
	ndr->depth++;
	if (r->blob == NULL || r->blob->data == NULL) {
		ndr_print_string(ndr, "attid", "NULL");
	} else if (r->blob->length < 4) {
		ndr_print_DATA_BLOB(ndr, "attid", *r->blob);
	} else {
		v = IVAL(r->blob->data, 0);
		ndr_print_uint32(ndr, "attid", v);
	}
	ndr->depth--;
}

static void _print_drsuapi_DsAttributeValue_str(struct ndr_print *ndr, const char *name,
						const struct drsuapi_DsAttributeValue *r)
{
	void *p;
	size_t converted_size = 0;

	ndr_print_struct(ndr, name, "drsuapi_DsAttributeValue");
	ndr->depth++;
	if (r->blob == NULL || r->blob->data == NULL) {
		ndr_print_string(ndr, "string", "NULL");
	} else if (!convert_string_talloc(ndr,
					  CH_UTF16, CH_UNIX,
					  r->blob->data,
					  r->blob->length,
					  &p, &converted_size)) {
		ndr_print_DATA_BLOB(ndr, "string (INVALID CONVERSION)",
				    *r->blob);
	} else {
		char *str = (char *)p;
		ndr_print_string(ndr, "string", str);
		TALLOC_FREE(str);
	}
	ndr->depth--;
}

static void _print_drsuapi_DsAttributeValueCtr(struct ndr_print *ndr,
					       const char *name,
					       const struct drsuapi_DsAttributeValueCtr *r,
					       void (*print_val_fn)(struct ndr_print *ndr, const char *name, const struct drsuapi_DsAttributeValue *r))
{
	uint32_t cntr_values_1;
	ndr_print_struct(ndr, name, "drsuapi_DsAttributeValueCtr");
	ndr->depth++;
	ndr_print_uint32(ndr, "num_values", r->num_values);
	ndr_print_ptr(ndr, "values", r->values);
	ndr->depth++;
	if (r->values) {
		ndr->print(ndr, "%s: ARRAY(%"PRIu32")", "values", r->num_values);
		ndr->depth++;
		for (cntr_values_1=0;cntr_values_1<r->num_values;cntr_values_1++) {
			char *idx_1=NULL;
			if (asprintf(&idx_1, "[%"PRIu32"]", cntr_values_1) != -1) {
				//ndr_print_drsuapi_DsAttributeValue(ndr, "values", &r->values[cntr_values_1]);
				print_val_fn(ndr, "values", &r->values[cntr_values_1]);
				free(idx_1);
			}
		}
		ndr->depth--;
	}
	ndr->depth--;
	ndr->depth--;
}

_PUBLIC_ void ndr_print_drsuapi_DsReplicaAttribute(struct ndr_print *ndr,
						   const char *name,
						   const struct drsuapi_DsReplicaAttribute *r)
{
	ndr_print_struct(ndr, name, "drsuapi_DsReplicaAttribute");
	ndr->depth++;
	ndr_print_drsuapi_DsAttributeId(ndr, "attid", r->attid);
	switch (r->attid) {
	case DRSUAPI_ATTID_objectClass:
	case DRSUAPI_ATTID_possSuperiors:
	case DRSUAPI_ATTID_subClassOf:
	case DRSUAPI_ATTID_governsID:
	case DRSUAPI_ATTID_mustContain:
	case DRSUAPI_ATTID_mayContain:
	case DRSUAPI_ATTID_rDNAttId:
	case DRSUAPI_ATTID_attributeID:
	case DRSUAPI_ATTID_attributeSyntax:
	case DRSUAPI_ATTID_auxiliaryClass:
	case DRSUAPI_ATTID_systemPossSuperiors:
	case DRSUAPI_ATTID_systemMayContain:
	case DRSUAPI_ATTID_systemMustContain:
	case DRSUAPI_ATTID_systemAuxiliaryClass:
	case DRSUAPI_ATTID_transportAddressAttribute:
		/* ATTIDs for classSchema and attributeSchema */
		_print_drsuapi_DsAttributeValueCtr(ndr, "value_ctr", &r->value_ctr,
		                                   _print_drsuapi_DsAttributeValue_attid);
		break;
	case DRSUAPI_ATTID_cn:
	case DRSUAPI_ATTID_ou:
	case DRSUAPI_ATTID_description:
	case DRSUAPI_ATTID_displayName:
	case DRSUAPI_ATTID_dMDLocation:
	case DRSUAPI_ATTID_adminDisplayName:
	case DRSUAPI_ATTID_adminDescription:
	case DRSUAPI_ATTID_lDAPDisplayName:
	case DRSUAPI_ATTID_name:
		_print_drsuapi_DsAttributeValueCtr(ndr, "value_ctr", &r->value_ctr,
		                                   _print_drsuapi_DsAttributeValue_str);
		break;
	default:
		_print_drsuapi_DsAttributeValueCtr(ndr, "value_ctr", &r->value_ctr,
		                                   ndr_print_drsuapi_DsAttributeValue);
		break;
	}
	ndr->depth--;
}

enum ndr_err_code ndr_push_drsuapi_DsGetNCChangesMSZIPCtr1(struct ndr_push *ndr, ndr_flags_type ndr_flags, const struct drsuapi_DsGetNCChangesMSZIPCtr1 *r)
{
	if (ndr_flags & NDR_SCALARS) {
		uint32_t decompressed_length = 0;
		uint32_t compressed_length = 0;
		if (r->ts) {
			{
				struct ndr_push *_ndr_ts;
				NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_ts, 4, -1));
				{
					struct ndr_push *_ndr_ts_compressed;
					NDR_CHECK(ndr_push_compression_state_init(_ndr_ts, NDR_COMPRESSION_MSZIP));
					NDR_CHECK(ndr_push_compression_start(_ndr_ts, &_ndr_ts_compressed));
					NDR_CHECK(ndr_push_drsuapi_DsGetNCChangesCtr1TS(_ndr_ts_compressed, NDR_SCALARS|NDR_BUFFERS, r->ts));
					decompressed_length = _ndr_ts_compressed->offset;
					NDR_CHECK(ndr_push_compression_end(_ndr_ts, _ndr_ts_compressed));
				}
				compressed_length = _ndr_ts->offset;
				TALLOC_FREE(_ndr_ts);
			}
		}
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, decompressed_length));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, compressed_length));
		NDR_CHECK(ndr_push_unique_ptr(ndr, r->ts));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->ts) {
			{
				struct ndr_push *_ndr_ts;
				NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_ts, 4, -1));
				{
					struct ndr_push *_ndr_ts_compressed;
					NDR_CHECK(ndr_push_compression_state_init(_ndr_ts, NDR_COMPRESSION_MSZIP));
					NDR_CHECK(ndr_push_compression_start(_ndr_ts, &_ndr_ts_compressed));
					NDR_CHECK(ndr_push_drsuapi_DsGetNCChangesCtr1TS(_ndr_ts_compressed, NDR_SCALARS|NDR_BUFFERS, r->ts));
					NDR_CHECK(ndr_push_compression_end(_ndr_ts, _ndr_ts_compressed));
				}
				NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_ts, 4, -1));
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_drsuapi_DsGetNCChangesMSZIPCtr6(struct ndr_push *ndr, ndr_flags_type ndr_flags, const struct drsuapi_DsGetNCChangesMSZIPCtr6 *r)
{
	if (ndr_flags & NDR_SCALARS) {
		uint32_t decompressed_length = 0;
		uint32_t compressed_length = 0;
		if (r->ts) {
			{
				struct ndr_push *_ndr_ts;
				NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_ts, 4, -1));
				{
					struct ndr_push *_ndr_ts_compressed;
					NDR_CHECK(ndr_push_compression_state_init(_ndr_ts, NDR_COMPRESSION_MSZIP));
					NDR_CHECK(ndr_push_compression_start(_ndr_ts, &_ndr_ts_compressed));
					NDR_CHECK(ndr_push_drsuapi_DsGetNCChangesCtr6TS(_ndr_ts_compressed, NDR_SCALARS|NDR_BUFFERS, r->ts));
					decompressed_length = _ndr_ts_compressed->offset;
					NDR_CHECK(ndr_push_compression_end(_ndr_ts, _ndr_ts_compressed));
				}
				compressed_length = _ndr_ts->offset;
				TALLOC_FREE(_ndr_ts);
			}
		}
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, decompressed_length));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, compressed_length));
		NDR_CHECK(ndr_push_unique_ptr(ndr, r->ts));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->ts) {
			{
				struct ndr_push *_ndr_ts;
				NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_ts, 4, -1));
				{
					struct ndr_push *_ndr_ts_compressed;
					NDR_CHECK(ndr_push_compression_state_init(_ndr_ts, NDR_COMPRESSION_MSZIP));
					NDR_CHECK(ndr_push_compression_start(_ndr_ts, &_ndr_ts_compressed));
					NDR_CHECK(ndr_push_drsuapi_DsGetNCChangesCtr6TS(_ndr_ts_compressed, NDR_SCALARS|NDR_BUFFERS, r->ts));
					NDR_CHECK(ndr_push_compression_end(_ndr_ts, _ndr_ts_compressed));
				}
				NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_ts, 4, -1));
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_drsuapi_DsGetNCChangesWIN2K3_LZ77_DIRECT2Ctr1(struct ndr_push *ndr, ndr_flags_type ndr_flags, const struct drsuapi_DsGetNCChangesWIN2K3_LZ77_DIRECT2Ctr1 *r)
{
	if (ndr_flags & NDR_SCALARS) {
		uint32_t decompressed_length = 0;
		uint32_t compressed_length = 0;
		if (r->ts) {
			{
				struct ndr_push *_ndr_ts;
				NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_ts, 4, -1));
				{
					struct ndr_push *_ndr_ts_compressed;
					NDR_CHECK(ndr_push_compression_state_init(_ndr_ts, NDR_COMPRESSION_WIN2K3_LZ77_DIRECT2));
					NDR_CHECK(ndr_push_compression_start(_ndr_ts, &_ndr_ts_compressed));
					NDR_CHECK(ndr_push_drsuapi_DsGetNCChangesCtr1TS(_ndr_ts_compressed, NDR_SCALARS|NDR_BUFFERS, r->ts));
					decompressed_length = _ndr_ts_compressed->offset;
					NDR_CHECK(ndr_push_compression_end(_ndr_ts, _ndr_ts_compressed));
				}
				compressed_length = _ndr_ts->offset;
				TALLOC_FREE(_ndr_ts);
			}
		}
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, decompressed_length));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, compressed_length));
		NDR_CHECK(ndr_push_unique_ptr(ndr, r->ts));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->ts) {
			{
				struct ndr_push *_ndr_ts;
				NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_ts, 4, -1));
				{
					struct ndr_push *_ndr_ts_compressed;
					NDR_CHECK(ndr_push_compression_state_init(_ndr_ts, NDR_COMPRESSION_WIN2K3_LZ77_DIRECT2));
					NDR_CHECK(ndr_push_compression_start(_ndr_ts, &_ndr_ts_compressed));
					NDR_CHECK(ndr_push_drsuapi_DsGetNCChangesCtr1TS(_ndr_ts_compressed, NDR_SCALARS|NDR_BUFFERS, r->ts));
					NDR_CHECK(ndr_push_compression_end(_ndr_ts, _ndr_ts_compressed));
				}
				NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_ts, 4, -1));
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_drsuapi_DsGetNCChangesWIN2K3_LZ77_DIRECT2Ctr6(struct ndr_push *ndr, ndr_flags_type ndr_flags, const struct drsuapi_DsGetNCChangesWIN2K3_LZ77_DIRECT2Ctr6 *r)
{
	if (ndr_flags & NDR_SCALARS) {
		uint32_t decompressed_length = 0;
		uint32_t compressed_length = 0;
		if (r->ts) {
			{
				struct ndr_push *_ndr_ts;
				NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_ts, 4, -1));
				{
					struct ndr_push *_ndr_ts_compressed;
					NDR_CHECK(ndr_push_compression_state_init(_ndr_ts, NDR_COMPRESSION_WIN2K3_LZ77_DIRECT2));
					NDR_CHECK(ndr_push_compression_start(_ndr_ts, &_ndr_ts_compressed));
					NDR_CHECK(ndr_push_drsuapi_DsGetNCChangesCtr6TS(_ndr_ts_compressed, NDR_SCALARS|NDR_BUFFERS, r->ts));
					decompressed_length = _ndr_ts_compressed->offset;
					NDR_CHECK(ndr_push_compression_end(_ndr_ts, _ndr_ts_compressed));
				}
				compressed_length = _ndr_ts->offset;
				TALLOC_FREE(_ndr_ts);
			}
		}
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, decompressed_length));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, compressed_length));
		NDR_CHECK(ndr_push_unique_ptr(ndr, r->ts));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->ts) {
			{
				struct ndr_push *_ndr_ts;
				NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_ts, 4, -1));
				{
					struct ndr_push *_ndr_ts_compressed;
					NDR_CHECK(ndr_push_compression_state_init(_ndr_ts, NDR_COMPRESSION_WIN2K3_LZ77_DIRECT2));
					NDR_CHECK(ndr_push_compression_start(_ndr_ts, &_ndr_ts_compressed));
					NDR_CHECK(ndr_push_drsuapi_DsGetNCChangesCtr6TS(_ndr_ts_compressed, NDR_SCALARS|NDR_BUFFERS, r->ts));
					NDR_CHECK(ndr_push_compression_end(_ndr_ts, _ndr_ts_compressed));
				}
				NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_ts, 4, -1));
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ size_t ndr_size_drsuapi_DsReplicaObjectIdentifier3Binary_without_Binary(const struct drsuapi_DsReplicaObjectIdentifier3Binary *r, libndr_flags flags)
{
	return ndr_size_struct((const struct drsuapi_DsReplicaObjectIdentifier3 *)r, flags, (ndr_push_flags_fn_t)ndr_push_drsuapi_DsReplicaObjectIdentifier3);
}

_PUBLIC_ void ndr_print_drsuapi_SecBufferType(struct ndr_print *ndr, const char *name, enum drsuapi_SecBufferType r)
{
	const char *val = NULL;

	switch (r & 0x00000007) {
		case DRSUAPI_SECBUFFER_EMPTY: val = "DRSUAPI_SECBUFFER_EMPTY"; break;
		case DRSUAPI_SECBUFFER_DATA: val = "DRSUAPI_SECBUFFER_DATA"; break;
		case DRSUAPI_SECBUFFER_TOKEN: val = "DRSUAPI_SECBUFFER_TOKEN"; break;
		case DRSUAPI_SECBUFFER_PKG_PARAMS: val = "DRSUAPI_SECBUFFER_PKG_PARAMS"; break;
		case DRSUAPI_SECBUFFER_MISSING: val = "DRSUAPI_SECBUFFER_MISSING"; break;
		case DRSUAPI_SECBUFFER_EXTRA: val = "DRSUAPI_SECBUFFER_EXTRA"; break;
		case DRSUAPI_SECBUFFER_STREAM_TRAILER: val = "DRSUAPI_SECBUFFER_STREAM_TRAILER"; break;
		case DRSUAPI_SECBUFFER_STREAM_HEADER: val = "DRSUAPI_SECBUFFER_STREAM_HEADER"; break;
	}

	if (r & DRSUAPI_SECBUFFER_READONLY) {
		char *v = talloc_asprintf(ndr, "DRSUAPI_SECBUFFER_READONLY | %s", val);
		ndr_print_enum(ndr, name, "ENUM", v, r);
	} else {
		ndr_print_enum(ndr, name, "ENUM", val, r);
	}
}

_PUBLIC_ void ndr_print_drsuapi_DsAddEntry_AttrErrListItem_V1(struct ndr_print *ndr, const char *name, const struct drsuapi_DsAddEntry_AttrErrListItem_V1 *r)
{
	ndr_print_struct(ndr, name, "drsuapi_DsAddEntry_AttrErrListItem_V1");
	ndr->depth++;
	ndr_print_ptr(ndr, "next", r->next);
	ndr_print_drsuapi_DsAddEntry_AttrErr_V1(ndr, "err_data", &r->err_data);
	ndr->depth--;
	if (r->next) {
		ndr_print_drsuapi_DsAddEntry_AttrErrListItem_V1(ndr, "next", r->next);
	}
}

enum ndr_err_code ndr_push_drsuapi_DsBindInfo(struct ndr_push *ndr, ndr_flags_type ndr_flags, const union drsuapi_DsBindInfo *r)
{
	libndr_flags _flags_save = ndr->flags;
	ndr->flags = ndr->flags & ~LIBNDR_FLAG_NDR64;
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		uint32_t level;
		NDR_CHECK(ndr_push_steal_switch_value(ndr, r, &level));
		NDR_CHECK(ndr_push_union_align(ndr, 4));
		switch (level) {
			case 24: {
				{
					struct ndr_push *_ndr_info24;
					NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_info24, 0, 24));
					NDR_CHECK(ndr_push_drsuapi_DsBindInfo24(_ndr_info24, NDR_SCALARS, &r->info24));
					NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_info24, 0, 24));
				}
			break; }

			case 28: {
				{
					struct ndr_push *_ndr_info28;
					NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_info28, 0, 28));
					NDR_CHECK(ndr_push_drsuapi_DsBindInfo28(_ndr_info28, NDR_SCALARS, &r->info28));
					NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_info28, 0, 28));
				}
			break; }

			case 48: {
				{
					struct ndr_push *_ndr_info48;
					NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_info48, 0, 48));
					NDR_CHECK(ndr_push_drsuapi_DsBindInfo48(_ndr_info48, NDR_SCALARS, &r->info48));
					NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_info48, 0, 48));
				}
			break; }

			case 52: {
				{
					struct ndr_push *_ndr_info52;
					NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_info52, 0, 52));
					NDR_CHECK(ndr_push_drsuapi_DsBindInfo52(_ndr_info52, NDR_SCALARS, &r->info52));
					NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_info52, 0, 52));
				}
			break; }

			default: {
				{
					struct ndr_push *_ndr_Fallback;
					NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_Fallback, 0, level));
					NDR_CHECK(ndr_push_drsuapi_DsBindInfoFallBack(_ndr_Fallback, NDR_SCALARS, &r->Fallback));
					NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_Fallback, 0, level));
				}
			break; }

		}
	}
	ndr->flags = _flags_save;
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_drsuapi_DsBindInfo(struct ndr_pull *ndr, ndr_flags_type ndr_flags, union drsuapi_DsBindInfo *r)
{
	libndr_flags _flags_save = ndr->flags;
	ndr->flags = ndr->flags & ~LIBNDR_FLAG_NDR64;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		uint32_t level;
		NDR_CHECK(ndr_pull_steal_switch_value(ndr, r, &level));
		NDR_CHECK(ndr_pull_union_align(ndr, 4));
		switch (level) {
			case 24: {
				{
					struct ndr_pull *_ndr_info24;
					NDR_CHECK(ndr_pull_subcontext_start(ndr, &_ndr_info24, 0, 24));
					NDR_CHECK(ndr_pull_drsuapi_DsBindInfo24(_ndr_info24, NDR_SCALARS, &r->info24));
					NDR_CHECK(ndr_pull_subcontext_end(ndr, _ndr_info24, 0, 24));
				}
			break; }

			case 28: {
				{
					struct ndr_pull *_ndr_info28;
					NDR_CHECK(ndr_pull_subcontext_start(ndr, &_ndr_info28, 0, 28));
					NDR_CHECK(ndr_pull_drsuapi_DsBindInfo28(_ndr_info28, NDR_SCALARS, &r->info28));
					NDR_CHECK(ndr_pull_subcontext_end(ndr, _ndr_info28, 0, 28));
				}
			break; }

			case 48: {
				{
					struct ndr_pull *_ndr_info48;
					NDR_CHECK(ndr_pull_subcontext_start(ndr, &_ndr_info48, 0, 48));
					NDR_CHECK(ndr_pull_drsuapi_DsBindInfo48(_ndr_info48, NDR_SCALARS, &r->info48));
					NDR_CHECK(ndr_pull_subcontext_end(ndr, _ndr_info48, 0, 48));
				}
			break; }

			case 52: {
				{
					struct ndr_pull *_ndr_info52;
					NDR_CHECK(ndr_pull_subcontext_start(ndr, &_ndr_info52, 0, 52));
					NDR_CHECK(ndr_pull_drsuapi_DsBindInfo52(_ndr_info52, NDR_SCALARS, &r->info52));
					NDR_CHECK(ndr_pull_subcontext_end(ndr, _ndr_info52, 0, 52));
				}
			break; }

			default: {
				{
					struct ndr_pull *_ndr_Fallback;
					NDR_CHECK(ndr_pull_subcontext_start(ndr, &_ndr_Fallback, 0, level));
					NDR_CHECK(ndr_pull_drsuapi_DsBindInfoFallBack(_ndr_Fallback, NDR_SCALARS, &r->Fallback));
					NDR_CHECK(ndr_pull_subcontext_end(ndr, _ndr_Fallback, 0, level));
				}
			break; }

		}
	}
	ndr->flags = _flags_save;
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_drsuapi_DsBindInfo(struct ndr_print *ndr, const char *name, const union drsuapi_DsBindInfo *r)
{
	uint32_t level;
	level = ndr_print_steal_switch_value(ndr, r);
	ndr_print_union(ndr, name, level, "drsuapi_DsBindInfo");
	switch (level) {
		case 24:
			ndr_print_drsuapi_DsBindInfo24(ndr, "info24", &r->info24);
		break;

		case 28:
			ndr_print_drsuapi_DsBindInfo28(ndr, "info28", &r->info28);
		break;

		case 48:
			ndr_print_drsuapi_DsBindInfo48(ndr, "info48", &r->info48);
		break;

		case 52:
			ndr_print_drsuapi_DsBindInfo52(ndr, "info52", &r->info52);
		break;

		default:
			ndr_print_drsuapi_DsBindInfoFallBack(ndr, "Fallback", &r->Fallback);
		break;

	}
}
