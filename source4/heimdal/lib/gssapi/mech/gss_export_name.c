/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Portions Copyright (c) 2010 Apple Inc. All rights reserved.
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
 *	$FreeBSD: src/lib/libgssapi/gss_export_name.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"

/**
 * Convert a GGS-API name from internal form to contiguous string.
 *
 * @sa gss_import_name(), @ref internalVSmechname.
 *
 * @param minor_status   minor status code
 * @param input_name     input name in internal name form
 * @param exported_name  output name in contiguos string form
 *
 * @returns a gss_error code, see gss_display_status() about printing
 *        the error code.
 *
 * @ingroup gssapi
 */
GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_export_name(OM_uint32 *minor_status,
    gss_const_name_t input_name,
    gss_buffer_t exported_name)
{
	struct _gss_name *name = (struct _gss_name *) input_name;
	struct _gss_mechanism_name *mn;

	_mg_buffer_zero(exported_name);

	/*
	 * If this name already has any attached MNs, export the first
	 * one, otherwise export based on the first mechanism in our
	 * list.
	 */
	mn = HEIM_TAILQ_FIRST(&name->gn_mn);
	if (!mn) {
		*minor_status = 0;
		return (GSS_S_NAME_NOT_MN);
	}

	return mn->gmn_mech->gm_export_name(minor_status,
	    mn->gmn_name, exported_name);
}

OM_uint32
gss_mg_export_name(OM_uint32 *minor_status,
		   const gss_const_OID mech,
		   const void *name,
		   size_t length, 
		   gss_buffer_t exported_name)
{
    uint8_t *buf;

    exported_name->length = 10 + length + mech->length;
    exported_name->value  = malloc(exported_name->length);
    if (exported_name->value == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    /* TOK, MECH_OID_LEN, DER(MECH_OID), NAME_LEN, NAME */

    buf = exported_name->value;
    memcpy(buf, "\x04\x01", 2);
    buf += 2;
    buf[0] = ((mech->length + 2) >> 8) & 0xff;
    buf[1] = (mech->length + 2) & 0xff;
    buf+= 2;
    buf[0] = 0x06;
    buf[1] = (mech->length) & 0xFF;
    buf+= 2;

    memcpy(buf, mech->elements, mech->length);
    buf += mech->length;

    buf[0] = (length >> 24) & 0xff;
    buf[1] = (length >> 16) & 0xff;
    buf[2] = (length >> 8) & 0xff;
    buf[3] = (length) & 0xff;
    buf += 4;

    memcpy (buf, name, length);

    *minor_status = 0;
    return GSS_S_COMPLETE;
}
