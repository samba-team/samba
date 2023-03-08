/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/lib/libgssapi/utils.h,v 1.1 2005/12/29 14:40:20 dfr Exp $
 *	$Id$
 */

OM_uint32 _gss_free_oid(OM_uint32 *, gss_OID);
OM_uint32 _gss_intern_oid(OM_uint32 *, gss_const_OID, gss_OID *);
OM_uint32 _gss_copy_buffer(OM_uint32 *minor_status,
    const gss_buffer_t from_buf, gss_buffer_t to_buf);
OM_uint32 _gss_secure_release_buffer(OM_uint32 *minor_status,
				     gss_buffer_t buffer);
OM_uint32 _gss_secure_release_buffer_set(OM_uint32 *minor_status,
					 gss_buffer_set_t *buffer_set);

void _gss_mg_encode_le_uint64(uint64_t n, uint8_t *p);
void _gss_mg_decode_le_uint64(const void *ptr, uint64_t *n);
void _gss_mg_encode_be_uint64(uint64_t n, uint8_t *p);
void _gss_mg_decode_be_uint64(const void *ptr, uint64_t *n);

void _gss_mg_encode_le_uint32(uint32_t n, uint8_t *p);
void _gss_mg_decode_le_uint32(const void *ptr, uint32_t *n);
void _gss_mg_encode_be_uint32(uint32_t n, uint8_t *p);
void _gss_mg_decode_be_uint32(const void *ptr, uint32_t *n);

void _gss_mg_encode_le_uint16(uint16_t n, uint8_t *p);
void _gss_mg_decode_le_uint16(const void *ptr, uint16_t *n);
void _gss_mg_encode_be_uint16(uint16_t n, uint8_t *p);
void _gss_mg_decode_be_uint16(const void *ptr, uint16_t *n);

OM_uint32
_gss_mg_import_rfc4121_context(OM_uint32 *minor,
			       uint8_t initiator_flag,
			       OM_uint32 gss_flags,
			       int32_t rfc3961_enctype,
			       gss_const_buffer_t session_key,
			       gss_ctx_id_t *rfc4121_context_handle);

#include <krb5.h>

/*
 * Note: functions below support zero-length OIDs and buffers and will
 * return NULL values. Callers should handle accordingly.
 */

OM_uint32
_gss_mg_ret_oid(OM_uint32 *minor,
		krb5_storage *sp,
		gss_OID *oidp);

OM_uint32
_gss_mg_store_oid(OM_uint32 *minor,
		  krb5_storage *sp,
		  gss_const_OID oid);

OM_uint32
_gss_mg_ret_buffer(OM_uint32 *minor,
		   krb5_storage *sp,
		   gss_buffer_t buffer);

OM_uint32
_gss_mg_store_buffer(OM_uint32 *minor,
		     krb5_storage *sp,
		     gss_const_buffer_t buffer);
