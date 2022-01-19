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
 *	$FreeBSD: src/lib/libgssapi/name.h,v 1.1 2005/12/29 14:40:20 dfr Exp $
 *	$Id$
 */

struct _gss_mechanism_name {
	HEIM_TAILQ_ENTRY(_gss_mechanism_name) gmn_link;
	gssapi_mech_interface	gmn_mech;	/* mechanism ops for MN */
	gss_OID			gmn_mech_oid;	/* mechanism oid for MN */
	gss_name_t		gmn_name;	/* underlying MN */
};
HEIM_TAILQ_HEAD(_gss_mechanism_name_list, _gss_mechanism_name);

struct _gss_name {
	gss_OID			gn_type;	/* type of name */
	gss_buffer_desc		gn_value;	/* value (as imported) */
	struct _gss_mechanism_name_list gn_mn;	/* list of MNs */
};

OM_uint32
	_gss_find_mn(OM_uint32 *, struct _gss_name *, gss_const_OID,
	      struct _gss_mechanism_name **);
struct _gss_name *
	_gss_create_name(gss_name_t new_mn, gssapi_mech_interface m);
void	_gss_mg_release_name(struct _gss_name *);


void	_gss_mg_check_name(gss_const_name_t name);

gss_name_t
	_gss_mg_get_underlying_mech_name(gss_name_t name, gss_const_OID mech);

OM_uint32
_gss_mech_import_name(OM_uint32 * minor_status,
		      gss_const_OID mech,
		      struct _gss_name_type *names,
		      const gss_buffer_t input_name_buffer,
		      gss_const_OID input_name_type,
		      gss_name_t *output_name);

OM_uint32
gss_mg_export_name(OM_uint32 *minor_status,
		   const gss_const_OID mech,
		   const void *name,
		   size_t length, 
		   gss_buffer_t exported_name);

OM_uint32
_gss_mech_inquire_names_for_mech(OM_uint32 * minor_status,
				 struct _gss_name_type *names,
				 gss_OID_set *name_types);


