/* 
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling DCOM string arrays

   Copyright (C) Jelmer Vernooij 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/
//#define NDR_CHECK_DEBUG
#include "includes.h"
#include "librpc/gen_ndr/ndr_dcom.h"
#include "librpc/gen_ndr/ndr_wmi.h"
#include "librpc/ndr/ndr_wmi.h"

// Just for debugging
int NDR_CHECK_depth = 0;
int NDR_CHECK_shift = 0x18;

int get_CIMTYPE_size(int t)
{
	if (t & CIM_FLAG_ARRAY) return 4;
	t &= 0x1FF;
	switch (t) {
        case CIM_SINT8:
        case CIM_UINT8:
		return 1;
        case CIM_SINT16:
        case CIM_UINT16:
        case CIM_BOOLEAN:
		return 2;
        case CIM_SINT32:
        case CIM_UINT32:
        case CIM_REAL32:
        case CIM_STRING:
        case CIM_DATETIME:
        case CIM_REFERENCE:
        case CIM_OBJECT:
		return 4;
        case CIM_SINT64:
        case CIM_UINT64:
        case CIM_REAL64:
		return 8;
	default:
		DEBUG(0, ("Unknown CIMTYPE size for %04X", t));
		return 4;
	}
}

enum ndr_err_code ndr_push_BSTR(struct ndr_push *ndr, int ndr_flags, const struct BSTR *r)
{
	uint32_t len;
	uint32_t flags;
	enum ndr_err_code status;
	len = strlen(r->data);
        if (ndr_flags & NDR_SCALARS) {
                NDR_CHECK(ndr_push_align(ndr, 4));
                NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0x72657355));
                NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, len));
                NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 2*len));
		flags = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_NOTERM | LIBNDR_FLAG_STR_SIZE4);
		status = ndr_push_string(ndr, NDR_SCALARS, r->data);
		ndr->flags = flags;
		return status;
        }
        return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_BSTR(struct ndr_pull *ndr, int ndr_flags, struct BSTR *r)
{
        return NDR_ERR_BAD_SWITCH;
}

void ndr_print_BSTR(struct ndr_print *ndr, const char *name, const struct BSTR *r)
{
	ndr->print(ndr, "%-25s: BSTR(\"%s\")", name, r->data);
}

enum ndr_err_code ndr_push_CIMSTRING(struct ndr_push *ndr, int ndr_flags, const CIMSTRING *r)
{
	uint8_t u;
	enum ndr_err_code status;

        if (!(ndr_flags & NDR_SCALARS)) return NDR_ERR_SUCCESS;

        NDR_CHECK(ndr_push_uint8(ndr, NDR_SCALARS, 0));
	u = ndr->flags;
	ndr->flags |= LIBNDR_FLAG_STR_ASCII | LIBNDR_FLAG_STR_NULLTERM;
	status = ndr_push_string(ndr, NDR_SCALARS, *r);
	DEBUG(9, ("%08X: Push string: %s\n", ndr->offset, *r));
	ndr->flags = u;
	return status;
}

enum ndr_err_code ndr_pull_CIMSTRING(struct ndr_pull *ndr, int ndr_flags, CIMSTRING *r)
{
	uint8_t u;
	enum ndr_err_code status;

        if (!(ndr_flags & NDR_SCALARS)) return NDR_ERR_SUCCESS;

        NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &u));
	switch (u) {
	case 0:
		u = ndr->flags;
		ndr->flags |= LIBNDR_FLAG_STR_ASCII | LIBNDR_FLAG_STR_NULLTERM;
		status = ndr_pull_string(ndr, NDR_SCALARS, r);
		DEBUG(10, ("%08X: Pull string: %s\n", ndr->offset, *r));
		ndr->flags = u;
		return status;
	case 1:
		u = ndr->flags;
		ndr->flags |= LIBNDR_FLAG_STR_NULLTERM;
		status = ndr_pull_string(ndr, NDR_SCALARS, r);
		DEBUG(10, ("%08X: Pull string: %s\n", ndr->offset, *r));
		ndr->flags = u;
		return status;
	default: return NDR_ERR_BAD_SWITCH;
	}
}

void ndr_print_CIMSTRING(struct ndr_print *ndr, const char *name, const CIMSTRING *r)
{
	ndr->print(ndr, "%-25s: \"%s\"", name, *r);
}

enum ndr_err_code ndr_push_CIMSTRINGS(struct ndr_push *ndr, int ndr_flags, const struct CIMSTRINGS *r)
{
	uint32_t ofs_size, ofs, i;

        if (!(ndr_flags & NDR_SCALARS)) return NDR_ERR_SUCCESS;

	ofs_size = ndr->offset;
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));

	for (i = 0; i < r->count; ++i) {
		ofs = ndr->offset;
		NDR_CHECK(ndr_push_CIMSTRING(ndr, ndr_flags, &r->item[i]));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ndr->offset - ofs));
	}
	ofs = ndr->offset;
	ndr->offset = ofs_size;
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ofs -  ofs_size));
	ndr->offset = ofs;

        return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_CIMSTRINGS(struct ndr_pull *ndr, int ndr_flags, struct CIMSTRINGS *r)
{
	uint32_t endofs;
	uint32_t len;
	TALLOC_CTX *mem_ctx;
	uint32_t u;

        if (!(ndr_flags & NDR_SCALARS)) return NDR_ERR_SUCCESS;

	mem_ctx = ndr->current_mem_ctx;

        NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &endofs));
	endofs += ndr->offset - sizeof(endofs);

	r->count = 0;
	len = 5;
	r->item = talloc_array(mem_ctx, CIMSTRING, len);
	ndr->current_mem_ctx = r->item;
	while (ndr->offset < endofs) {
		if (r->count >= len) {
			len += 3;
			r->item = talloc_realloc(mem_ctx, r->item, CIMSTRING, len);
		}
		NDR_CHECK(ndr_pull_CIMSTRING(ndr, ndr_flags, &r->item[r->count]));
    		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
		++r->count;
	}

	r->item = talloc_realloc(mem_ctx, r->item, CIMSTRING, r->count);

	ndr->current_mem_ctx = mem_ctx;

        return NDR_ERR_SUCCESS;
}

static const char *qualifier_keys[] = {[1] = "key", [3] = "read", [6] = "provider", [7] = "dynamic", [10] = "CIMTYPE" };
#define arr_sizeof(a) (sizeof(a)/sizeof(a[0]))
static const char *qn_unknown = "Unknown_qualifier_name";

_PUBLIC_ enum ndr_err_code ndr_push_WbemQualifier(struct ndr_push *ndr, int ndr_flags, const struct WbemQualifier *r)
{
        if (ndr_flags & NDR_SCALARS) {
                NDR_CHECK(ndr_push_align(ndr, 4));
            	NDR_CHECK(ndr_push_relative_ptr1(ndr, r->name));
                NDR_CHECK(ndr_push_WBEM_FLAVOR_TYPE(ndr, NDR_SCALARS, r->flavors));
                NDR_CHECK(ndr_push_CIMTYPE_ENUMERATION(ndr, NDR_SCALARS, r->cimtype));
                NDR_CHECK(ndr_push_set_switch_value(ndr, &r->value, r->cimtype & CIM_TYPEMASK));
                NDR_CHECK(ndr_push_CIMVAR(ndr, NDR_SCALARS, &r->value));
        }
        if (ndr_flags & NDR_BUFFERS) {
                if (r->name) {
			uint32_t ofs;
			int32_t i;
			for (i = 0; i < arr_sizeof(qualifier_keys); ++i)
				if (qualifier_keys[i] && !strcmp(r->name, qualifier_keys[i])) break;
			if (i == arr_sizeof(qualifier_keys)) {
				if (!strncmp(qn_unknown, r->name, sizeof(qn_unknown) - 1))
                            		i = atoi(r->name + sizeof(qn_unknown) - 1);
				else
					i = -1;
			}
			if (i >= 0) {
				ofs = ndr->offset;
				NDR_CHECK(ndr_token_retrieve(&ndr->relative_list, r->name, &ndr->offset));
				NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0x80000000 | i));
				ndr->offset = ofs;
			} else {
                    		NDR_CHECK(ndr_push_relative_ptr2(ndr, r->name));
                    		NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->name));
			}
                }
                NDR_CHECK(ndr_push_CIMVAR(ndr, NDR_BUFFERS, &r->value));
        }
        return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_WbemQualifier(struct ndr_pull *ndr, int ndr_flags, struct WbemQualifier *r)
{
        uint32_t _ptr_name;
        TALLOC_CTX *_mem_save_name_0;
        if (ndr_flags & NDR_SCALARS) {
                NDR_CHECK(ndr_pull_align(ndr, 4));
                NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_name));
                if (_ptr_name != 0xFFFFFFFF) {
                        NDR_PULL_ALLOC(ndr, r->name);
                        NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->name, _ptr_name));
                } else {
                        r->name = NULL;
                }
                NDR_CHECK(ndr_pull_WBEM_FLAVOR_TYPE(ndr, NDR_SCALARS, &r->flavors));
                NDR_CHECK(ndr_pull_CIMTYPE_ENUMERATION(ndr, NDR_SCALARS, &r->cimtype));
                NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->value, r->cimtype & CIM_TYPEMASK));
                NDR_CHECK(ndr_pull_CIMVAR(ndr, NDR_SCALARS, &r->value));
        }
        if (ndr_flags & NDR_BUFFERS) {
		uint32_t relofs;
		relofs = ndr_token_peek(&ndr->relative_list, r->name);
		if (relofs & 0x80000000) {
			relofs &= 0xFF;
			if ((relofs < sizeof(qualifier_keys)/sizeof(qualifier_keys[0])) && qualifier_keys[relofs]) {
				r->name = talloc_strdup(ndr->current_mem_ctx, qualifier_keys[relofs]);
			} else {
				r->name = talloc_asprintf(ndr->current_mem_ctx, "%s%d", qn_unknown, relofs);
			}
		} else if (r->name) {
                        uint32_t _relative_save_offset;
			_relative_save_offset = ndr->offset;
                        NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->name));
                        _mem_save_name_0 = NDR_PULL_GET_MEM_CTX(ndr);
                        NDR_PULL_SET_MEM_CTX(ndr, r->name, 0);
                        NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->name));
                        NDR_PULL_SET_MEM_CTX(ndr, _mem_save_name_0, 0);
                        ndr->offset = _relative_save_offset;
                }
                NDR_CHECK(ndr_pull_CIMVAR(ndr, NDR_BUFFERS, &r->value));
        }
        return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_WbemQualifiers(struct ndr_push *ndr, int ndr_flags, const struct WbemQualifiers *r)
{
	uint32_t i, ofs, ofs_size;

        if (ndr_flags & NDR_SCALARS) {
		ofs_size = ndr->offset;
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));
		for (i = 0; i < r->count; ++i)
			NDR_CHECK(ndr_push_WbemQualifier(ndr, NDR_SCALARS, r->item[i]));
		ofs = ndr->offset;
		ndr->offset = ofs_size;
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ofs - ofs_size));
		ndr->offset = ofs;
	}
	if (ndr_flags & NDR_BUFFERS) {
		for (i = 0; i < r->count; ++i)
			NDR_CHECK(ndr_push_WbemQualifier(ndr, NDR_BUFFERS, r->item[i]));
	}
        return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemQualifiers(struct ndr_pull *ndr, int ndr_flags, struct WbemQualifiers *r)
{
	uint32_t endofs;
	uint32_t len;
	TALLOC_CTX *mem_ctx;

	mem_ctx = ndr->current_mem_ctx;

        if (ndr_flags & NDR_SCALARS) {
	        NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &endofs));
		endofs += ndr->offset - 4;

		r->count = 0;
		len = 10;
		r->item = talloc_array(mem_ctx, struct WbemQualifier*, len);
		ndr->current_mem_ctx = r->item;
		while (ndr->offset < endofs) {
			if (r->count >= len) {
				len += 3;
				r->item = talloc_realloc(mem_ctx, r->item, struct WbemQualifier*, len);
			}
			NDR_PULL_ALLOC(ndr, r->item[r->count]);
			NDR_CHECK(ndr_pull_WbemQualifier(ndr, NDR_SCALARS, r->item[r->count]));
			++r->count;
		}
		r->item = talloc_realloc(mem_ctx, r->item, struct WbemQualifier*, r->count);
	}
        if (ndr_flags & NDR_BUFFERS) {
		uint32_t i;
		ndr->current_mem_ctx = r->item;
		for (i = 0; i < r->count; ++i) {
			NDR_CHECK(ndr_pull_WbemQualifier(ndr, NDR_BUFFERS, r->item[i]));
		}
	}

	ndr->current_mem_ctx = mem_ctx;

        return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_DataWithStack(struct ndr_push *ndr, ndr_push_flags_fn_t fn, const void *r)
{
	uint32_t ofs, ofs_size, ofs_ssize;

	ofs_size = ndr->offset;
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));

	NDR_CHECK(fn(ndr, NDR_SCALARS, r));

	ofs_ssize = ndr->offset;
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));
	ndr->relative_base_offset = ndr->offset;

	NDR_CHECK(fn(ndr, NDR_BUFFERS, r));

	ofs = ndr->offset;
	ndr->offset = ofs_size;
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ofs-ofs_size));
	ndr->offset = ofs_ssize;
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, (ofs-ofs_ssize-4) | 0x80000000));
	ndr->offset = ofs;

        return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_DataWithStack(struct ndr_pull *ndr, ndr_pull_flags_fn_t fn, void *r)
{
	uint32_t end, size, ssize, ndrend;

	end = ndr->offset;
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &size));
	NDR_PULL_NEED_BYTES(ndr, size - 4);
	end += size;
	ndrend = ndr->data_size;
	ndr->data_size = end;

	NDR_CHECK(fn(ndr, NDR_SCALARS, r));

	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &ssize));
	if (!(ssize & 0x80000000))
		return ndr_pull_error(ndr, NDR_ERR_VALIDATE, "ndr_pull_DataWithStack(%08X): Stack size without 31th bit set: 0x%08X", ndr->offset - 4, ssize);
	ssize &= 0x7FFFFFFF;
	NDR_PULL_NEED_BYTES(ndr, ssize);
	ndr->data_size = ndr->offset + ssize;

	ndr->relative_base_offset = ndr->offset;

	NDR_CHECK(fn(ndr, NDR_BUFFERS, r));

	ndr->data_size = ndrend;
	ndr->offset = end;

        return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_uint32_flags(struct ndr_push *ndr, int ndr_flags, uint32_t v)
{
	if (ndr_flags & NDR_SCALARS)
		return ndr_push_uint32(ndr, NDR_SCALARS, v);
        return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_uint32_flags(struct ndr_pull *ndr, int ndr_flags, uint32_t *v)
{
	if (ndr_flags & NDR_SCALARS)
		return ndr_pull_uint32(ndr, NDR_SCALARS, v);
        return NDR_ERR_SUCCESS;
}

void copy_bits(const uint8_t *src, uint32_t bsrc, uint8_t *dst, uint32_t bdst, uint32_t count)
{
	uint8_t mask;

	src += bsrc >> 3;
	bsrc &= 7;
	dst += bdst >> 3;
	bdst &= 7;
	mask = ((1 << count) - 1);
	*dst &= ~(mask << bdst);
	*dst |= ((*src >> bsrc) & mask) << bdst;
}

#define IS_CIMTYPE_PTR(t) (((t) & CIM_FLAG_ARRAY) || ((t) == CIM_STRING) || ((t) == CIM_DATETIME) || ((t) == CIM_REFERENCE))
enum ndr_err_code ndr_push_WbemInstance_priv(struct ndr_push *ndr, int ndr_flags, const struct WbemClassObject *r)
{
	int i;
	if (ndr_flags & NDR_SCALARS) {
		uint32_t ofs, vofs;

		NDR_CHECK(ndr_push_uint8(ndr, NDR_SCALARS, r->instance->u1_0));

                if (r->instance->__CLASS) {
                        NDR_CHECK(ndr_push_relative_ptr1(ndr, r->instance->__CLASS));
                } else {
                        NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0xFFFFFFFF));
                }

		ofs = ndr->offset;
		NDR_PUSH_NEED_BYTES(ndr, r->obj_class->data_size);

		for (i = 0; i < r->obj_class->__PROPERTY_COUNT; ++i) {
			copy_bits(&r->instance->properties[i].default_flags, 0, ndr->data + ndr->offset, 2*r->obj_class->properties[i].property.desc->nr, 2);
		}
		i = 0xFF;
		copy_bits((uint8_t *)&i, 0, ndr->data + ndr->offset, 2*r->obj_class->__PROPERTY_COUNT, (8 - 2*r->obj_class->__PROPERTY_COUNT) % 7);
		vofs = ofs + ((r->obj_class->__PROPERTY_COUNT + 3) >> 2);

		for (i = 0; i < r->obj_class->__PROPERTY_COUNT; ++i) {
			NDR_CHECK(ndr_push_set_switch_value(ndr, &r->instance->data[i], r->obj_class->properties[i].property.desc->cimtype & CIM_TYPEMASK));
			ndr->offset = vofs + r->obj_class->properties[i].property.desc->offset;
			NDR_CHECK(ndr_push_CIMVAR(ndr, NDR_SCALARS, &r->instance->data[i]));
		}
		ndr->offset = ofs + r->obj_class->data_size;

		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->instance->u2_4));
		NDR_CHECK(ndr_push_uint8(ndr, NDR_SCALARS, r->instance->u3_1));
	}
	if (ndr_flags & NDR_BUFFERS) {
                if (r->instance->__CLASS) {
                        NDR_CHECK(ndr_push_relative_ptr2(ndr, r->instance->__CLASS));
                        NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->instance->__CLASS));
                }
                for (i = 0; i < r->obj_class->__PROPERTY_COUNT; ++i) {
			NDR_CHECK(ndr_push_CIMVAR(ndr, NDR_BUFFERS, &r->instance->data[i]));
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemInstance_priv(struct ndr_pull *ndr, int ndr_flags, const struct WbemClassObject *r)
{
	int i;

	if (!r->obj_class) {
DEBUG(1,("ndr_pull_WbemInstance_priv: There is no class for given instance\n"));
		return NDR_ERR_VALIDATE;
	}
        ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
	if (ndr_flags & NDR_SCALARS) {
		uint32_t ofs, vofs;
		uint32_t _ptr___CLASS;

		NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->instance->u1_0));

                NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr___CLASS));
                if (_ptr___CLASS != 0xFFFFFFFF) {
                        NDR_PULL_ALLOC(ndr, r->instance->__CLASS);
                        NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->instance->__CLASS, _ptr___CLASS));
                } else {
                        r->instance->__CLASS = NULL;
                }

		ofs = ndr->offset;
		NDR_PULL_NEED_BYTES(ndr, r->obj_class->data_size);
                NDR_PULL_ALLOC_N(ndr, r->instance->default_flags, r->obj_class->__PROPERTY_COUNT);
		for (i = 0; i < r->obj_class->__PROPERTY_COUNT; ++i) {
			r->instance->default_flags[i] = 0;
			copy_bits(ndr->data + ndr->offset, 2*r->obj_class->properties[i].property.desc->nr, &r->instance->properties[i].default_flags, 0, 2);
		}
		vofs = ofs + ((r->obj_class->__PROPERTY_COUNT + 3) >> 2);

                NDR_PULL_ALLOC_N(ndr, r->instance->data, r->obj_class->__PROPERTY_COUNT);
		memset(r->instance->data, 0, sizeof(*r->instance->data) * r->obj_class->__PROPERTY_COUNT);
                for (i = 0; i < r->obj_class->__PROPERTY_COUNT; ++i) {
			NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->instance->data[i], r->obj_class->properties[i].property.desc->cimtype & CIM_TYPEMASK));
			ndr->offset = vofs + r->obj_class->properties[i].property.desc->offset;
			NDR_CHECK(ndr_pull_CIMVAR(ndr, NDR_SCALARS, &r->instance->data[i]));
		}
		ndr->offset = ofs + r->obj_class->data_size;

		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->instance->u2_4));
		NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->instance->u3_1));
	}
	if (ndr_flags & NDR_BUFFERS) {
                if (r->instance->__CLASS) {
                        uint32_t _relative_save_offset;
                        _relative_save_offset = ndr->offset;
			NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->instance->__CLASS));
                        NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->instance->__CLASS));
                        ndr->offset = _relative_save_offset;
                }
                for (i = 0; i < r->obj_class->__PROPERTY_COUNT; ++i) {
			NDR_CHECK(ndr_pull_CIMVAR(ndr, NDR_BUFFERS, &r->instance->data[i]));
		}
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_WbemInstance_priv(struct ndr_print *ndr, const char *name, const struct WbemClassObject *r)
{
	int i;

	ndr_print_array_uint8(ndr, "default_flags", r->instance->default_flags, r->obj_class->__PROPERTY_COUNT);

	ndr->print(ndr, "%s: ARRAY(%d)", "data", r->obj_class->__PROPERTY_COUNT);
	ndr->depth++;
	for (i = 0; i < r->obj_class->__PROPERTY_COUNT; ++i) {
		ndr->print(ndr, "%s[%d]", "data", i);
		ndr->depth++;
		ndr_print_set_switch_value(ndr, &r->instance->data[i], r->obj_class->properties[i].property.desc->cimtype & CIM_TYPEMASK);
		ndr_print_CIMVAR(ndr, r->obj_class->properties[i].property.name, &r->instance->data[i]);
		ndr->depth--;
	}
	ndr->depth--;
}

enum ndr_err_code ndr_push_WbemClassObject(struct ndr_push *ndr, int ndr_flags, const struct WbemClassObject *r)
{
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
        NDR_CHECK(ndr_push_uint8(ndr, NDR_SCALARS, r->flags));
	if (r->flags & WCF_CLASS) {
                NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->__SERVER));
                NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->__NAMESPACE));
	}
	if (r->flags & WCF_DECORATIONS) {
		NDR_CHECK(ndr_push_DataWithStack(ndr, (ndr_push_flags_fn_t)ndr_push_WbemClass, r->sup_class));
		NDR_CHECK(ndr_push_DataWithStack(ndr, (ndr_push_flags_fn_t)ndr_push_WbemMethods, r->sup_methods));
	}
	if (r->flags & (WCF_CLASS | WCF_INSTANCE)) {
		NDR_CHECK(ndr_push_DataWithStack(ndr, (ndr_push_flags_fn_t)ndr_push_WbemClass, r->obj_class));
	}
	if (r->flags & WCF_DECORATIONS) {
		NDR_CHECK(ndr_push_DataWithStack(ndr, (ndr_push_flags_fn_t)ndr_push_WbemMethods, r->obj_methods));
	}
	if (r->flags & WCF_INSTANCE) {
		NDR_CHECK(ndr_push_DataWithStack(ndr, (ndr_push_flags_fn_t)ndr_push_WbemInstance_priv, r));
	}
        return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemClassObject(struct ndr_pull *ndr, int ndr_flags, struct WbemClassObject *r)
{
	TALLOC_CTX *tc;

	tc = NDR_PULL_GET_MEM_CTX(ndr);
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
        NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->flags));
	if (r->flags & WCF_CLASS) {
                NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->__SERVER));
                NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->__NAMESPACE));
	}
	if (r->flags & WCF_DECORATIONS) {
		r->sup_class = talloc_zero(r, struct WbemClass);
		NDR_PULL_SET_MEM_CTX(ndr, r->sup_class, 0);
		NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)ndr_pull_WbemClass, r->sup_class));
		r->sup_methods = talloc_zero(r, struct WbemMethods);
		NDR_PULL_SET_MEM_CTX(ndr, r->sup_methods, 0);
		NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)ndr_pull_WbemMethods, r->sup_methods));
		NDR_PULL_SET_MEM_CTX(ndr, tc, 0);
	} else
		r->sup_class = NULL;
	if (r->flags & (WCF_CLASS | WCF_INSTANCE)) {
		r->obj_class = talloc_zero(r, struct WbemClass);
		NDR_PULL_SET_MEM_CTX(ndr, r->obj_class, 0);
		NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)ndr_pull_WbemClass, r->obj_class));
		NDR_PULL_SET_MEM_CTX(ndr, tc, 0);
	}
	if (r->flags & WCF_DECORATIONS) {
		r->obj_methods = talloc_zero(r, struct WbemMethods);
		NDR_PULL_SET_MEM_CTX(ndr, r->obj_methods, 0);
		NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)ndr_pull_WbemMethods, r->obj_methods));
		NDR_PULL_SET_MEM_CTX(ndr, tc, 0);
	}
	if (r->flags & WCF_INSTANCE) {
		r->instance = talloc_zero(r, struct WbemInstance);
		NDR_PULL_SET_MEM_CTX(ndr, r->instance, 0);
		NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)ndr_pull_WbemInstance_priv, r));
		NDR_PULL_SET_MEM_CTX(ndr, tc, 0);
	} else
		r->instance = NULL;
        return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemClassObject_Object(struct ndr_pull *ndr, int ndr_flags, struct WbemClassObject *r)
{
	TALLOC_CTX *tc;

	tc = NDR_PULL_GET_MEM_CTX(ndr);
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
        NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->flags));
	if (r->flags & WCF_CLASS) {
                NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->__SERVER));
                NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->__NAMESPACE));
	}
	if (r->flags & WCF_INSTANCE) {
		r->instance = talloc_zero(r, struct WbemInstance);
		NDR_PULL_SET_MEM_CTX(ndr, r->instance, 0);
		NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)ndr_pull_WbemInstance_priv, r));
		NDR_PULL_SET_MEM_CTX(ndr, tc, 0);
	} else
		r->instance = NULL;
        return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_WbemClassObject(struct ndr_print *ndr, const char *name, const struct WbemClassObject *r)
{
        ndr_print_struct(ndr, name, "WbemClassObject");
        {
                uint32_t _flags_save_STRUCT = ndr->flags;
                ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
                ndr->depth++;
                ndr_print_WCO_FLAGS(ndr, "flags", r->flags);
	if (r->flags & WCF_CLASS) {
    		ndr_print_ptr(ndr, "__SERVER", r->__SERVER);
    		ndr->depth++;
    		ndr_print_CIMSTRING(ndr, "__SERVER", &r->__SERVER);
    		ndr->depth--;
                ndr_print_ptr(ndr, "__NAMESPACE", r->__NAMESPACE);
                ndr->depth++;
                ndr_print_CIMSTRING(ndr, "__NAMESPACE", &r->__NAMESPACE);
                ndr->depth--;
	}
	if (r->flags & WCF_DECORATIONS) {
                ndr_print_ptr(ndr, "sup_class", r->sup_class);
                ndr->depth++;
                if (r->sup_class) {
                        ndr_print_WbemClass(ndr, "sup_class", r->sup_class);
                }
                ndr->depth--;
                ndr_print_ptr(ndr, "sup_methods", r->sup_methods);
                ndr->depth++;
                if (r->sup_methods) {
                        ndr_print_WbemMethods(ndr, "sup_methods", r->sup_methods);
                }
                ndr->depth--;
	}
	if (r->flags & (WCF_CLASS | WCF_INSTANCE)) {
                ndr_print_ptr(ndr, "obj_class", r->obj_class);
                ndr->depth++;
                if (r->obj_class) {
                        ndr_print_WbemClass(ndr, "obj_class", r->obj_class);
                }
                ndr->depth--;
	}
	if (r->flags & WCF_DECORATIONS) {
                ndr_print_ptr(ndr, "obj_methods", r->obj_methods);
                ndr->depth++;
                if (r->obj_methods) {
                        ndr_print_WbemMethods(ndr, "obj_methods", r->obj_methods);
                }
                ndr->depth--;
	}
	if (r->flags & WCF_INSTANCE) {
                ndr_print_ptr(ndr, "instance", r->instance);
                ndr->depth++;
                if (r->instance) {
                        ndr_print_WbemInstance_priv(ndr, "instance", r);
                }
                ndr->depth--;
	}
                ndr->depth--;
                ndr->flags = _flags_save_STRUCT;
        }
}

_PUBLIC_ enum ndr_err_code ndr_push_WbemClass(struct ndr_push *ndr, int ndr_flags, const struct WbemClass *r)
{
        uint32_t cntr_properties_0;
	uint32_t i, ofs, vofs;
        {
                uint32_t _flags_save_STRUCT = ndr->flags;
                ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
                if (ndr_flags & NDR_SCALARS) {
                        NDR_CHECK(ndr_push_align(ndr, 4));
                        NDR_CHECK(ndr_push_uint8(ndr, NDR_SCALARS, r->u_0));
                        if (r->__CLASS) {
                                NDR_CHECK(ndr_push_relative_ptr1(ndr, r->__CLASS));
                        } else {
                                NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0xFFFFFFFF));
                        }
                        NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->data_size));
                        NDR_CHECK(ndr_push_CIMSTRINGS(ndr, NDR_SCALARS, &r->__DERIVATION));
                        NDR_CHECK(ndr_push_WbemQualifiers(ndr, NDR_SCALARS, &r->qualifiers));
                        NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->__PROPERTY_COUNT));
                        for (cntr_properties_0 = 0; cntr_properties_0 < r->__PROPERTY_COUNT; cntr_properties_0++) {
                                NDR_CHECK(ndr_push_WbemProperty(ndr, NDR_SCALARS, &r->properties[cntr_properties_0].property));
                        }

			ofs = ndr->offset;
			NDR_PUSH_NEED_BYTES(ndr, r->data_size);

			for (i = 0; i < r->__PROPERTY_COUNT; ++i) {
				copy_bits(&r->properties[i].default_flags, 0, ndr->data + ndr->offset, 2*r->properties[i].property.desc->nr, 2);
			}
			i = 0xFF;
			copy_bits((uint8_t *)&i, 0, ndr->data + ndr->offset, 2*r->__PROPERTY_COUNT, (8 - 2*r->__PROPERTY_COUNT) % 7);
			vofs = ofs + ((r->__PROPERTY_COUNT + 3) >> 2);
			for (i = 0; i < r->__PROPERTY_COUNT; ++i) {
				NDR_CHECK(ndr_push_set_switch_value(ndr, &r->properties[i].default_values, r->properties[i].property.desc->cimtype & CIM_TYPEMASK));
				ndr->offset = vofs + r->properties[i].property.desc->offset;
				if ((r->properties[i].default_flags & DEFAULT_FLAG_EMPTY) && IS_CIMTYPE_PTR(r->properties[i].property.desc->cimtype & CIM_TYPEMASK)) {
                    			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0xFFFFFFFF));
				} else {
					NDR_CHECK(ndr_push_CIMVAR(ndr, NDR_SCALARS, &r->properties[i].default_values));
				}
			}
			ndr->offset = ofs + r->data_size;
                }
                if (ndr_flags & NDR_BUFFERS) {
                        if (r->__CLASS) {
                                NDR_CHECK(ndr_push_relative_ptr2(ndr, r->__CLASS));
                                NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->__CLASS));
                        }
                        NDR_CHECK(ndr_push_CIMSTRINGS(ndr, NDR_BUFFERS, &r->__DERIVATION));
                        NDR_CHECK(ndr_push_WbemQualifiers(ndr, NDR_BUFFERS, &r->qualifiers));
                        for (cntr_properties_0 = 0; cntr_properties_0 < r->__PROPERTY_COUNT; cntr_properties_0++) {
                                NDR_CHECK(ndr_push_WbemProperty(ndr, NDR_BUFFERS, &r->properties[cntr_properties_0].property));
                        }
			for (i = 0; i < r->__PROPERTY_COUNT; ++i) {
				if (r->properties[i].default_flags & DEFAULT_FLAG_EMPTY) continue;
				NDR_CHECK(ndr_push_CIMVAR(ndr, NDR_BUFFERS, &r->properties[i].default_values));
			}
                }
                ndr->flags = _flags_save_STRUCT;
        }
        return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_WbemClass(struct ndr_pull *ndr, int ndr_flags, struct WbemClass *r)
{
        uint32_t _ptr___CLASS;
        uint32_t cntr_properties_0;
        TALLOC_CTX *_mem_save_properties_0;
	uint32_t i;

        {
                uint32_t _flags_save_STRUCT = ndr->flags;

                ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
                if (ndr_flags & NDR_SCALARS) {
                        NDR_CHECK(ndr_pull_align(ndr, 4));
                        NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->u_0));
                        NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr___CLASS));
                        if (_ptr___CLASS != 0xFFFFFFFF) {
                                NDR_PULL_ALLOC(ndr, r->__CLASS);
                                NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->__CLASS, _ptr___CLASS));
                        } else {
                                r->__CLASS = NULL;
                        }
                        NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->data_size));
                        NDR_CHECK(ndr_pull_CIMSTRINGS(ndr, NDR_SCALARS, &r->__DERIVATION));
                        NDR_CHECK(ndr_pull_WbemQualifiers(ndr, NDR_SCALARS, &r->qualifiers));
                        NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->__PROPERTY_COUNT));
                        NDR_PULL_ALLOC_N(ndr, r->properties, r->__PROPERTY_COUNT);
                        _mem_save_properties_0 = NDR_PULL_GET_MEM_CTX(ndr);
                        NDR_PULL_SET_MEM_CTX(ndr, r->properties, 0);
                        for (cntr_properties_0 = 0; cntr_properties_0 < r->__PROPERTY_COUNT; cntr_properties_0++) {
                                NDR_CHECK(ndr_pull_WbemProperty(ndr, NDR_SCALARS, &(r->properties)[cntr_properties_0]));
                        }
                        NDR_PULL_SET_MEM_CTX(ndr, _mem_save_properties_0, 0);

			NDR_PULL_NEED_BYTES(ndr, r->data_size);

                        NDR_PULL_ALLOC_N(ndr, r->default_flags, r->__PROPERTY_COUNT);
                        NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->default_flags, ndr->offset));

                        NDR_PULL_ALLOC_N(ndr, r->default_values, r->__PROPERTY_COUNT);
			memset(r->default_values, 0, sizeof(*r->default_values) * r->__PROPERTY_COUNT);
                        NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->default_values, ndr->offset + ((r->__PROPERTY_COUNT + 3) >> 2)));

			ndr->offset += r->data_size;
                }
                if (ndr_flags & NDR_BUFFERS) {
                        if (r->__CLASS) {
				TALLOC_CTX *_mem_save___CLASS_0;
                                uint32_t _relative_save_offset;
                    		_relative_save_offset = ndr->offset;
				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->__CLASS));
				_mem_save___CLASS_0 = NDR_PULL_GET_MEM_CTX(ndr);
				NDR_PULL_SET_MEM_CTX(ndr, r->__CLASS, 0);
                                NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->__CLASS));
				NDR_PULL_SET_MEM_CTX(ndr, _mem_save___CLASS_0, 0);
                                ndr->offset = _relative_save_offset;
                        }
                        NDR_CHECK(ndr_pull_CIMSTRINGS(ndr, NDR_BUFFERS, &r->__DERIVATION));
                        NDR_CHECK(ndr_pull_WbemQualifiers(ndr, NDR_BUFFERS, &r->qualifiers));
                        _mem_save_properties_0 = NDR_PULL_GET_MEM_CTX(ndr);
                        NDR_PULL_SET_MEM_CTX(ndr, r->properties, 0);
                        for (cntr_properties_0 = 0; cntr_properties_0 < r->__PROPERTY_COUNT; cntr_properties_0++) {
                                NDR_CHECK(ndr_pull_WbemProperty(ndr, NDR_BUFFERS, &(r->properties)[cntr_properties_0].property));
                        }
                        NDR_PULL_SET_MEM_CTX(ndr, _mem_save_properties_0, 0);
			{
				uint32_t ofs;
				NDR_CHECK(ndr_token_retrieve(&ndr->relative_list, r->default_flags, &ofs));
				for (i = 0; i < r->__PROPERTY_COUNT; ++i) {
					r->properties[i].default_flags = 0;
					copy_bits(ndr->data + ofs, 2*r->properties[i].property.desc->nr, &r->properties[i].default_flags, 0, 2);
				}
			}
			{
				uint32_t ofs;
				uint32_t _relative_save_offset;
                    		_relative_save_offset = ndr->offset;
				NDR_CHECK(ndr_token_retrieve(&ndr->relative_list, r->default_values, &ofs));
				for (i=0; i < r->__PROPERTY_COUNT; ++i) {
					if (r->properties[i].default_flags & DEFAULT_FLAG_EMPTY) continue;
					NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->properties[i].default_values, r->properties[i].property.desc->cimtype & CIM_TYPEMASK));
					ndr->offset = ofs + r->properties[i].property.desc->offset;
					NDR_CHECK(ndr_pull_CIMVAR(ndr, NDR_SCALARS|NDR_BUFFERS, &r->properties[i].default_values));
				}
                                ndr->offset = _relative_save_offset;
			}
                }
                ndr->flags = _flags_save_STRUCT;
        }
        return NDR_ERR_SUCCESS;
}
