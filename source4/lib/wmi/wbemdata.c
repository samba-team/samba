/*
   WMI Implementation
   Copyright (C) 2006 Andrzej Hajda <andrzej.hajda@wp.pl>

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

#include "includes.h"
#include "librpc/gen_ndr/dcom.h"
#include "librpc/gen_ndr/com_dcom.h"
#include "librpc/ndr/libndr.h"
#include "librpc/ndr/libndr_proto.h"
#include "lib/com/com.h"
#include "lib/com/dcom/dcom.h"
#include "lib/util/dlinklist.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_dcom.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "lib/talloc/talloc.h"
#include "libcli/composite/composite.h"
#include "wmi/proto.h"

NTSTATUS ndr_pull_WbemClassObject_Object(struct ndr_pull *ndr, int ndr_flags, struct WbemClassObject *r);
void duplicate_CIMVAR(TALLOC_CTX *mem_ctx, const union CIMVAR *src, union CIMVAR *dst, enum CIMTYPE_ENUMERATION cimtype);
void duplicate_WbemClassObject(TALLOC_CTX *mem_ctx, const struct WbemClassObject *src, struct WbemClassObject *dst);

#define NDR_CHECK_LEN(n) do { if (p + (n) > pend) { \
            			DEBUG(0, ("%s(%d): WBEMDATA_ERR(0x%08X): Buffer too small(0x%04X)\n", __FILE__, __LINE__, ndr->offset, p + (n) - pend)); \
				status = NT_STATUS_UNSUCCESSFUL; \
            			goto end; \
			    } \
			} while(0)

#define NDR_CHECK_EXPR(expr) do { if (!(expr)) {\
					DEBUG(0, ("%s(%d): WBEMDATA_ERR(0x%08X): Error parsing(%s)\n", __FILE__, __LINE__, ndr->offset, #expr)); \
					status = NT_STATUS_UNSUCCESSFUL; \
            				goto end; \
					} \
				    } while(0)

#define NDR_CHECK_CONST(val, exp) NDR_CHECK_EXPR((val) == (exp))
#define NDR_CHECK_RSTRING(rstring) NDR_CHECK_EXPR((rstring) >= 0)

#define NTERR_CHECK(call) status = call; if (!NT_STATUS_IS_OK(status)) goto end;

enum {
	DATATYPE_CLASSOBJECT = 2,
	DATATYPE_OBJECT = 3,

	COFLAG_IS_CLASS = 4,
};

static NTSTATUS marshal(struct IUnknown *pv, struct OBJREF *o)
{
	struct ndr_push *ndr;
	NTSTATUS status;
	struct WbemClassObject *wco;
	TALLOC_CTX *mem_ctx;
	struct MInterfacePointer *mp;

	mp = (struct MInterfacePointer *)((char *)o - offsetof(struct MInterfacePointer, obj)); // FIXME:high remove this Mumbo Jumbo
	wco = pv->object_data;
	mem_ctx = talloc_new(0);
	ndr = talloc_zero(mem_ctx, struct ndr_push);
	ndr->flags = 0;
	ndr->alloc_size = 1024;
	ndr->data = talloc_array(mp, uint8_t, ndr->alloc_size);

	if (wco) {
		uint32_t ofs;
		NTERR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0x12345678));
		NTERR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));
		NTERR_CHECK(ndr_push_WbemClassObject(ndr, NDR_SCALARS | NDR_BUFFERS, wco));
		ofs = ndr->offset;
		ndr->offset = 4;
		NTERR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ofs - 8));
		ndr->offset = ofs;
	} else {
		NTERR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));
	}
	o->u_objref.u_custom.pData = talloc_realloc(mp, ndr->data, uint8_t, ndr->offset);
	o->u_objref.u_custom.size = ndr->offset;
	mp->size = sizeof(struct OBJREF) - sizeof(union OBJREF_Types) + sizeof(struct u_custom) + o->u_objref.u_custom.size - 4;
        if (DEBUGLVL(9)) {
		NDR_PRINT_DEBUG(WbemClassObject, wco);
	}
end:
	talloc_free(mem_ctx);
	return status;
}

static NTSTATUS unmarshal(struct OBJREF *o, struct IUnknown **pv)
{
	struct ndr_pull *ndr;
	TALLOC_CTX *mem_ctx;
	struct WbemClassObject *wco;
	NTSTATUS status;
	uint32_t u;

	mem_ctx = talloc_new(0);
	ndr = talloc_zero(mem_ctx, struct ndr_pull);
	ndr->current_mem_ctx = mem_ctx;
	ndr->data = o->u_objref.u_custom.pData;
	ndr->data_size = o->u_objref.u_custom.size;

	NTERR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	if (!u) {
		talloc_free(*pv);
		*pv = NULL;
		status = NT_STATUS_OK;
		goto end;
	}
	NTERR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	if (u + 8 > ndr->data_size) {
		DEBUG(1, ("unmarshall_IWbemClassObject: Incorrect data_size"));
		status = NT_STATUS_BUFFER_TOO_SMALL;
		goto end;
	}
	wco = talloc_zero(*pv, struct WbemClassObject);
	ndr->current_mem_ctx = wco;
	status = ndr_pull_WbemClassObject(ndr, NDR_SCALARS | NDR_BUFFERS, wco);

        if (NT_STATUS_IS_OK(status) && (DEBUGLVL(9))) {
		NDR_PRINT_DEBUG(WbemClassObject, wco);
        }

	if (NT_STATUS_IS_OK(status)) {
		(*pv)->object_data = wco;
	} else {
		talloc_free(wco);
	}
end:
	talloc_free(mem_ctx);
	return status;
}

WERROR dcom_IWbemClassObject_from_WbemClassObject(struct com_context *ctx, struct IWbemClassObject **_p, struct WbemClassObject *wco)
{
	struct IWbemClassObject *p;


	p = talloc_zero(ctx, struct IWbemClassObject);
	p->ctx = ctx;
	p->obj.signature = 0x574f454d;
	p->obj.flags = OBJREF_CUSTOM;
	GUID_from_string("dc12a681-737f-11cf-884d-00aa004b2e24", &p->obj.iid);
	GUID_from_string("4590f812-1d3a-11d0-891f-00aa004b2e24", &p->obj.u_objref.u_custom.clsid);
	p->object_data = (void *)wco;
	talloc_steal(p, p->object_data);
	*_p = p;
	return WERR_OK;
}

WERROR IWbemClassObject_GetMethod(struct IWbemClassObject *d, TALLOC_CTX *mem_ctx, const char *name, uint32_t flags, struct IWbemClassObject **in, struct IWbemClassObject **out)
{
	uint32_t i;
	struct WbemClassObject *wco;

	wco = (struct WbemClassObject *)d->object_data;
	for (i = 0; i < wco->obj_methods->count; ++i)
		if (!strcmp(wco->obj_methods->method[i].name, name)) {
			if (in) dcom_IWbemClassObject_from_WbemClassObject(d->ctx, in, wco->obj_methods->method[i].in);
			if (out) dcom_IWbemClassObject_from_WbemClassObject(d->ctx, out, wco->obj_methods->method[i].out);
			return WERR_OK;
		}
	return WERR_NOT_FOUND;
}

void WbemClassObject_CreateInstance(struct WbemClassObject *wco)
{
	uint32_t i;

	wco->instance = talloc_zero(wco, struct WbemInstance);
	wco->instance->default_flags = talloc_array(wco->instance, uint8_t, wco->obj_class->__PROPERTY_COUNT);
	wco->instance->data = talloc_array(wco->instance, union CIMVAR, wco->obj_class->__PROPERTY_COUNT);
	memset(wco->instance->data, 0, sizeof(union CIMVAR) * wco->obj_class->__PROPERTY_COUNT);
	for (i = 0; i < wco->obj_class->__PROPERTY_COUNT; ++i) {
		wco->instance->default_flags[i] = 1; // FIXME:high resolve this magic
	}
	wco->instance->__CLASS = wco->obj_class->__CLASS;
	wco->instance->u2_4 = 4;
	wco->instance->u3_1 = 1;
}

WERROR IWbemClassObject_Clone(struct IWbemClassObject *d, TALLOC_CTX *mem_ctx, struct IWbemClassObject **copy)
{
	return WERR_NOT_SUPPORTED;
}

WERROR IWbemClassObject_SpawnInstance(struct IWbemClassObject *d, TALLOC_CTX *mem_ctx, uint32_t flags, struct IWbemClassObject **instance)
{
	struct WbemClassObject *wco, *nwco;

	wco = (struct WbemClassObject *)d->object_data;
	nwco = talloc_zero(mem_ctx, struct WbemClassObject);
	nwco->flags = WCF_INSTANCE;
	nwco->obj_class = wco->obj_class;
	WbemClassObject_CreateInstance(nwco);
	dcom_IWbemClassObject_from_WbemClassObject(d->ctx, instance, nwco);
	return WERR_OK;
}

void duplicate_WbemQualifier(TALLOC_CTX *mem_ctx, const struct WbemQualifier *src, struct WbemQualifier *dst)
{
	dst->name = src->name;
	if (src->name) dst->name = talloc_strdup(mem_ctx, src->name);

	dst->flavors = src->flavors;

	dst->cimtype = src->cimtype;

	duplicate_CIMVAR(mem_ctx, &src->value, &dst->value, src->cimtype);
}

void duplicate_CIMSTRINGS(TALLOC_CTX *mem_ctx, const struct CIMSTRINGS *src, struct CIMSTRINGS *dst)
{
	uint32_t i;

	dst->count = src->count;
	for (i = 0; i < src->count; ++i)
		dst->item[i] = talloc_strdup(mem_ctx, src->item[i]);
}

void duplicate_WbemQualifiers(TALLOC_CTX *mem_ctx, const struct WbemQualifiers *src, struct WbemQualifiers *dst)
{
	uint32_t i;

	dst->count = src->count;
	for (i = 0; i < src->count; ++i) {
		dst->item[i] = talloc_zero(mem_ctx, struct WbemQualifier);
		duplicate_WbemQualifier(dst->item[i], src->item[i], dst->item[i]);
	}
}

void duplicate_WbemClass(TALLOC_CTX *mem_ctx, const struct WbemClass *src, struct WbemClass *dst)
{
	uint32_t i;

	dst->u_0 = src->u_0;

	dst->__CLASS = src->__CLASS;
	if (src->__CLASS) dst->__CLASS = talloc_strdup(mem_ctx, src->__CLASS);

	duplicate_CIMSTRINGS(mem_ctx, &src->__DERIVATION, &dst->__DERIVATION);
	duplicate_WbemQualifiers(mem_ctx, &src->qualifiers, &dst->qualifiers);

	dst->__PROPERTY_COUNT = src->__PROPERTY_COUNT;

	dst->properties = talloc_array(mem_ctx, struct WbemProperty, src->__PROPERTY_COUNT);
	for (i = 0; i < src->__PROPERTY_COUNT; ++i) {
		dst->properties[i].name = talloc_strdup(dst->properties, src->properties[i].name);
		dst->properties[i].desc = talloc_memdup(dst->properties, src->properties[i].desc, sizeof(*src->properties[i].desc));
		duplicate_WbemQualifiers(dst->properties[i].desc, &src->properties[i].desc->qualifiers, &dst->properties[i].desc->qualifiers);
	}

	dst->default_flags = talloc_array(mem_ctx, uint8_t, src->__PROPERTY_COUNT);
	dst->default_values = talloc_array(mem_ctx, union CIMVAR, src->__PROPERTY_COUNT);
	for (i = 0; i < src->__PROPERTY_COUNT; ++i) {
		dst->default_flags[i] = src->default_flags[i];
		duplicate_CIMVAR(dst->default_values, &src->default_values[i], &dst->default_values[i], src->properties[i].desc->cimtype);
	}
}

void duplicate_WbemMethod(TALLOC_CTX *mem_ctx, const struct WbemMethod *src, struct WbemMethod *dst)
{
	dst->name = src->name;
	if (src->name) dst->name = talloc_strdup(mem_ctx, src->name);
	
	dst->u0 = src->u0;
	dst->u1 = src->u1;
	
	dst->qualifiers = talloc_zero(mem_ctx, struct WbemQualifiers);
	duplicate_WbemQualifiers(dst->qualifiers, src->qualifiers, dst->qualifiers);

	dst->in = src->in;
	if (src->in) {
		dst->in = talloc_zero(mem_ctx, struct WbemClassObject);
		duplicate_WbemClassObject(dst->in, src->in, dst->in);
	}

	dst->out = src->out;
	if (src->out) {
		dst->out = talloc_zero(mem_ctx, struct WbemClassObject);
		duplicate_WbemClassObject(dst->out, src->out, dst->out);
	}
}

void duplicate_WbemMethods(TALLOC_CTX *mem_ctx, const struct WbemMethods *src, struct WbemMethods *dst)
{
	uint32_t i;

	dst->count = src->count;
	dst->u0 = src->u0;
	for (i = 0; i < src->count; ++i)
		duplicate_WbemMethod(mem_ctx, &src->method[i], &dst->method[i]);
}

void duplicate_WbemInstance(TALLOC_CTX *mem_ctx, const struct WbemInstance *src, struct WbemInstance *dst, const struct WbemClass *cls)
{
	uint32_t i;

	dst->u1_0 = src->u1_0;
	
	dst->__CLASS = src->__CLASS;
	if (src->__CLASS) dst->__CLASS = talloc_strdup(mem_ctx, src->__CLASS);

	dst->default_flags = talloc_array(mem_ctx, uint8_t, cls->__PROPERTY_COUNT);
	dst->data = talloc_array(mem_ctx, union CIMVAR, cls->__PROPERTY_COUNT);
	for (i = 0; i < cls->__PROPERTY_COUNT; ++i) {
		dst->default_flags[i] = src->default_flags[i];
		duplicate_CIMVAR(dst->data, &src->data[i], &dst->data[i], cls->properties[i].desc->cimtype);
	}

	dst->u2_4 = src->u2_4;
	dst->u3_1 = src->u3_1;
}

void duplicate_WbemClassObject(TALLOC_CTX *mem_ctx, const struct WbemClassObject *src, struct WbemClassObject *dst)
{
	dst->flags = src->flags;
	if (src->flags & WCF_CLASS) {
		dst->__SERVER = talloc_strdup(mem_ctx, src->__SERVER);
		dst->__NAMESPACE = talloc_strdup(mem_ctx, src->__NAMESPACE);
	}
	if (src->flags & WCF_DECORATIONS) {
		dst->sup_class = talloc_zero(mem_ctx, struct WbemClass);
		duplicate_WbemClass(dst->sup_class, src->sup_class, dst->sup_class);

		dst->sup_methods = talloc_zero(mem_ctx, struct WbemMethods);
		duplicate_WbemMethods(dst->sup_methods, src->sup_methods, dst->sup_methods);

		dst->obj_methods = talloc_zero(mem_ctx, struct WbemMethods);
		duplicate_WbemMethods(dst->obj_methods, src->obj_methods, dst->obj_methods);
	}
	if (src->flags & (WCF_CLASS | WCF_INSTANCE)) {
		dst->obj_class = talloc_zero(mem_ctx, struct WbemClass);
		duplicate_WbemClass(dst->obj_class, src->obj_class, dst->obj_class);
	}
	if (src->flags & WCF_INSTANCE) {
		dst->instance = talloc_zero(mem_ctx, struct WbemInstance);
		duplicate_WbemInstance(dst->instance, src->instance, dst->instance, src->obj_class);
	}
}

void duplicate_CIMVAR(TALLOC_CTX *mem_ctx, const union CIMVAR *src, union CIMVAR *dst, enum CIMTYPE_ENUMERATION cimtype)
{
	uint32_t i;

	switch (cimtype & CIM_TYPEMASK) {
        case CIM_SINT8:
        case CIM_UINT8:
        case CIM_SINT16:
        case CIM_UINT16:
        case CIM_SINT32:
        case CIM_UINT32:
        case CIM_SINT64:
        case CIM_UINT64:
        case CIM_REAL32:
        case CIM_REAL64:
        case CIM_BOOLEAN:
		*dst = *src;
		break;
        case CIM_STRING:
        case CIM_DATETIME:
        case CIM_REFERENCE:
		dst->v_string = talloc_strdup(mem_ctx, src->v_string);
		break;
	case CIM_OBJECT:
		dst->v_object = talloc_zero(mem_ctx, struct WbemClassObject);
		duplicate_WbemClassObject(dst->v_object, src->v_object, dst->v_object);
		break;
        case CIM_ARR_SINT8:
	case CIM_ARR_UINT8:
		dst->a_uint8 = talloc_memdup(mem_ctx, src->a_uint8, sizeof(struct arr_uint8));
		dst->a_uint8->item = talloc_memdup(dst->a_uint8, src->a_uint8->item, src->a_uint8->count);
		break;
        case CIM_ARR_SINT16:
        case CIM_ARR_UINT16:
        case CIM_ARR_BOOLEAN:
		dst->a_uint8 = talloc_memdup(mem_ctx, src->a_uint8, sizeof(struct arr_uint8));
		dst->a_uint8->item = talloc_memdup(dst->a_uint8, src->a_uint8->item, 2*src->a_uint8->count);
		break;
        case CIM_ARR_SINT32:
        case CIM_ARR_UINT32:
        case CIM_ARR_REAL32:
		dst->a_uint8 = talloc_memdup(mem_ctx, src->a_uint8, sizeof(struct arr_uint8));
		dst->a_uint8->item = talloc_memdup(dst->a_uint8, src->a_uint8->item, 4*src->a_uint8->count);
		break;
        case CIM_ARR_SINT64:
        case CIM_ARR_UINT64:
	case CIM_ARR_REAL64:
		dst->a_uint8 = talloc_memdup(mem_ctx, src->a_uint8, sizeof(struct arr_uint8));
		dst->a_uint8->item = talloc_memdup(dst->a_uint8, src->a_uint8->item, 8*src->a_uint8->count);
		break;
        case CIM_ARR_STRING:
        case CIM_ARR_DATETIME:
        case CIM_ARR_REFERENCE:
		dst->a_uint8 = talloc_memdup(mem_ctx, src->a_uint8, sizeof(struct arr_uint8));
		dst->a_uint8->item = talloc_memdup(dst->a_uint8, src->a_uint8->item, 4*src->a_uint8->count);
		for (i = 0; i < src->a_uint8->count; ++i)
			dst->a_string->item[i] = talloc_strdup(dst->a_uint8->item, src->a_string->item[i]);
		break;
	default:
    		DEBUG(0, ("duplicate_CIMVAR: cimtype 0x%04X not supported\n", cimtype & CIM_TYPEMASK));
		break;
	}
}

WERROR WbemClassObject_Get(struct WbemClassObject *d, TALLOC_CTX *mem_ctx, const char *name, uint32_t flags, union CIMVAR *val, enum CIMTYPE_ENUMERATION *cimtype, uint32_t *flavor)
{
	uint32_t i;
	for (i = 0; i < d->obj_class->__PROPERTY_COUNT; ++i) {
		if (!strcmp(d->obj_class->properties[i].name, name)) {
			duplicate_CIMVAR(mem_ctx, &d->instance->data[i], val, d->obj_class->properties[i].desc->cimtype);
			if (cimtype) *cimtype = d->obj_class->properties[i].desc->cimtype;
			if (flavor) *flavor = 0; // FIXME:avg implement flavor
			return WERR_OK;
		}
	}
	return WERR_NOT_FOUND;
}

WERROR IWbemClassObject_Put(struct IWbemClassObject *d, TALLOC_CTX *mem_ctx, const char *name, uint32_t flags, union CIMVAR *val, enum CIMTYPE_ENUMERATION cimtype)
{
	struct WbemClassObject *wco;
	uint32_t i;

	wco = (struct WbemClassObject *)d->object_data;
	for (i = 0; i < wco->obj_class->__PROPERTY_COUNT; ++i) {
		if (!strcmp(wco->obj_class->properties[i].name, name)) {
			if (cimtype && cimtype != wco->obj_class->properties[i].desc->cimtype) return WERR_INVALID_PARAM;
			wco->instance->default_flags[i] = 0;
			duplicate_CIMVAR(wco->instance, val, &wco->instance->data[i], wco->obj_class->properties[i].desc->cimtype);
			return WERR_OK;
		}
	}
	return WERR_NOT_FOUND;
}

#define WERR_CHECK(msg) if (!W_ERROR_IS_OK(result)) { \
                            DEBUG(1, ("ERROR: %s - %s\n", msg, wmi_errstr(result))); \
                            goto end; \
                        } else { \
                            DEBUG(1, ("OK   : %s\n", msg)); \
                        }

struct pair_guid_ptr {
	struct GUID guid;
	void *ptr;
	struct pair_guid_ptr *next, *prev;
};

static void *get_ptr_by_guid(struct pair_guid_ptr *list, struct GUID *uuid)
{
	for (; list; list = list->next) {
            	if (GUID_equal(&list->guid, uuid))
			return list->ptr;
	}
	return NULL;
}

static void add_pair_guid_ptr(TALLOC_CTX *mem_ctx, struct pair_guid_ptr **list, struct GUID *uuid, void *ptr)
{
	struct pair_guid_ptr *e;

	e = talloc(mem_ctx, struct pair_guid_ptr);
	e->guid = *uuid;
	e->ptr = ptr;
	talloc_steal(e, ptr);
	DLIST_ADD(*list, e);
}

struct IEnumWbemClassObject_data {
	struct GUID guid;
        struct IWbemFetchSmartEnum *pFSE;
	struct IWbemWCOSmartEnum *pSE;
	struct pair_guid_ptr *cache;
};

static NTSTATUS WBEMDATA_Parse(uint8_t *data, uint32_t size, struct IEnumWbemClassObject *d, uint32_t uCount, struct WbemClassObject **apObjects)
{
	struct ndr_pull *ndr;
	TALLOC_CTX *mem_ctx;
	uint32_t u, i, ofs_next;
	uint8_t u8, datatype;
	NTSTATUS status;
	struct GUID guid;
	struct IEnumWbemClassObject_data *ecod;

	if (!uCount) return NT_STATUS_NOT_IMPLEMENTED;

	ecod = d->object_data;
	mem_ctx = talloc_new(0);

	ndr = talloc_zero(mem_ctx, struct ndr_pull);
	ndr->current_mem_ctx = d->ctx;
	ndr->data = data;
	ndr->data_size = size;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);

	NDR_CHECK_set_shift(0x18);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, 0x0);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, *(const uint32_t *)"WBEM");
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, *(const uint32_t *)"DATA");
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, 0x1A); /* Length of header */
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_PULL_NEED_BYTES(ndr, u + 6);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, 0x0);
	NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &u8));
	NDR_CHECK_CONST(u8, 0x01); /* Major Version */
	NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &u8));
	NDR_CHECK_EXPR(u8 <= 1); /* Minor Version 0 - Win2000, 1 - XP/2003 */
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, 0x8); /* Length of header */
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_PULL_NEED_BYTES(ndr, u);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, 0xC); /* Length of header */
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_PULL_NEED_BYTES(ndr, u + 4);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, uCount);
	for (i = 0; i < uCount; ++i) {
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
		NDR_CHECK_CONST(u, 0x9); /* Length of header */
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
		NDR_PULL_NEED_BYTES(ndr, u + 1);
		NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &datatype));
		ofs_next = ndr->offset + u;
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
		NDR_CHECK_CONST(u, 0x18); /* Length of header */
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
		NDR_PULL_NEED_BYTES(ndr, u + 16);
		NDR_CHECK(ndr_pull_GUID(ndr, NDR_SCALARS, &guid));
		switch (datatype) {
		case DATATYPE_CLASSOBJECT:
			apObjects[i] = talloc_zero(d->ctx, struct WbemClassObject);
			ndr->current_mem_ctx = apObjects[i];
			NDR_CHECK(ndr_pull_WbemClassObject(ndr, NDR_SCALARS|NDR_BUFFERS, apObjects[i]));
			ndr->current_mem_ctx = d->ctx;
			add_pair_guid_ptr(ecod, &ecod->cache, &guid, apObjects[i]->obj_class);
			break;
		case DATATYPE_OBJECT:
			apObjects[i] = talloc_zero(d->ctx, struct WbemClassObject);
			apObjects[i]->obj_class = get_ptr_by_guid(ecod->cache, &guid);
			(void)talloc_reference(apObjects[i], apObjects[i]->obj_class);
			ndr->current_mem_ctx = apObjects[i];
			NDR_CHECK(ndr_pull_WbemClassObject_Object(ndr, NDR_SCALARS|NDR_BUFFERS, apObjects[i]));
			ndr->current_mem_ctx = d->ctx;
			break;
		default:
			DEBUG(0, ("WBEMDATA_Parse: Data type %d not supported\n", datatype));
			status = NT_STATUS_NOT_SUPPORTED;
			goto end;
		}
		ndr->offset = ofs_next;
    		if (DEBUGLVL(9)) {
			NDR_PRINT_DEBUG(WbemClassObject, apObjects[i]);
		}
	}
	status = NT_STATUS_OK;
end:
	talloc_free(mem_ctx);
	return status;
}

struct composite_context *dcom_proxy_IEnumWbemClassObject_Release_send(struct IUnknown *d, TALLOC_CTX *mem_ctx);

WERROR IEnumWbemClassObject_SmartNext(struct IEnumWbemClassObject *d, TALLOC_CTX *mem_ctx, int32_t lTimeout, uint32_t uCount, struct WbemClassObject **apObjects, uint32_t *puReturned)
{
	WERROR result;
	NTSTATUS status;
	struct IEnumWbemClassObject_data *ecod;
	TALLOC_CTX *loc_ctx;
	uint32_t size;
	uint8_t *data;

	loc_ctx = talloc_new(0);
	ecod = d->object_data;
	if (!ecod) {
	        struct GUID iid;
		WERROR coresult;

		d->object_data = ecod = talloc_zero(d, struct IEnumWbemClassObject_data);
    		GUID_from_string(COM_IWBEMFETCHSMARTENUM_UUID, &iid);
    		result = dcom_query_interface((struct IUnknown *)d, 5, 1, &iid, (struct IUnknown **)&ecod->pFSE, &coresult);
	        WERR_CHECK("dcom_query_interface.");
    		result = coresult;
	        WERR_CHECK("Retrieve enumerator of result(IWbemFetchSmartEnum).");

	        result = IWbemFetchSmartEnum_Fetch(ecod->pFSE, mem_ctx, &ecod->pSE);
    		WERR_CHECK("Retrieve enumerator of result(IWbemWCOSmartEnum).");

		ecod->guid = GUID_random();
		d->vtable->Release_send = dcom_proxy_IEnumWbemClassObject_Release_send;
	}

	result = IWbemWCOSmartEnum_Next(ecod->pSE, loc_ctx, &ecod->guid, lTimeout, uCount, puReturned, &size, &data);
	if (!W_ERROR_EQUAL(result, WERR_BADFUNC)) {
    		WERR_CHECK("IWbemWCOSmartEnum_Next.");
	}

	if (data) {
		status = WBEMDATA_Parse(data, size, d, *puReturned, apObjects);
		result = ntstatus_to_werror(status);
    		WERR_CHECK("WBEMDATA_Parse.");
	}
end:
	if (!W_ERROR_IS_OK(result)) {
    		status = werror_to_ntstatus(result);
    		DEBUG(9, ("dcom_proxy_IEnumWbemClassObject_Next: %s - %s\n", nt_errstr(status), get_friendly_nt_error_msg(status)));
	}
	talloc_free(loc_ctx);
	return result;
}

struct composite_context *dcom_proxy_IEnumWbemClassObject_Release_send(struct IUnknown *d, TALLOC_CTX *mem_ctx)
{
        struct composite_context *c, *cr;
        struct REMINTERFACEREF iref[3];
        struct dcom_object_exporter *ox;
	struct IEnumWbemClassObject_data *ecod;
	int n;

        c = composite_create(d->ctx, d->ctx->event_ctx);
        if (c == NULL) return NULL;
        c->private_data = d;

        ox = object_exporter_by_ip(d->ctx, d);
        iref[0].ipid = IUnknown_ipid(d);
        iref[0].cPublicRefs = 5;
        iref[0].cPrivateRefs = 0;
	n = 1;

	ecod = d->object_data;
	if (ecod) {
		if (ecod->pFSE) {
			talloc_steal(d, ecod->pFSE);
	    		iref[n].ipid = IUnknown_ipid(ecod->pFSE);
	    		iref[n].cPublicRefs = 5;
    			iref[n].cPrivateRefs = 0;
			++n;
		}
		if (ecod->pSE) {
			talloc_steal(d, ecod->pSE);
		        iref[n].ipid = IUnknown_ipid(ecod->pSE);
	    		iref[n].cPublicRefs = 5;
        		iref[n].cPrivateRefs = 0;
			++n;
		}
	}
	cr = IRemUnknown_RemRelease_send(ox->rem_unknown, mem_ctx, n, iref);

        composite_continue(c, cr, dcom_release_continue, c);
        return c;
}

NTSTATUS dcom_proxy_IWbemClassObject_init()
{
	struct GUID clsid;
	GUID_from_string("4590f812-1d3a-11d0-891f-00aa004b2e24", &clsid);
	dcom_register_marshal(&clsid, marshal, unmarshal);

#if 0
	struct IEnumWbemClassObject_vtable *proxy_vtable;
	proxy_vtable = (struct IEnumWbemClassObject_vtable *)dcom_proxy_vtable_by_iid((struct GUID *)&dcerpc_table_IEnumWbemClassObject.syntax_id.uuid);
	if (proxy_vtable)
		proxy_vtable->Release_send = dcom_proxy_IEnumWbemClassObject_Release_send;
	else
		DEBUG(0, ("WARNING: IEnumWbemClassObject should be initialized before IWbemClassObject."));
#endif

        return NT_STATUS_OK;
}
