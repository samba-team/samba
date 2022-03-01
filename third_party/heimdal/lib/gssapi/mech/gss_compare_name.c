/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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
 *	$FreeBSD: src/lib/libgssapi/gss_compare_name.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_compare_name(OM_uint32 *minor_status,
    gss_const_name_t name1_arg,
    gss_const_name_t name2_arg,
    int *name_equal)
{
	struct _gss_name *name1 = (struct _gss_name *) name1_arg;
	struct _gss_name *name2 = (struct _gss_name *) name2_arg;

	/*
	 * First check the implementation-independant name if both
	 * names have one. Otherwise, try to find common mechanism
	 * names and compare them.
	 */
       if (name1->gn_value.value && name2->gn_value.value &&
	    name1->gn_type == GSS_C_NO_OID && name2->gn_type == GSS_C_NO_OID) {
	    *name_equal =
		name1->gn_value.length == name2->gn_value.length &&
		memcmp(name1->gn_value.value, name2->gn_value.value,
		       name1->gn_value.length) == 0;
	} else if (name1->gn_value.value && name2->gn_value.value &&
		   name1->gn_type != GSS_C_NO_OID &&
		   name2->gn_type != GSS_C_NO_OID) {
		*name_equal = 1;
		/* RFC 2743: anonymous names always compare false */
		if (gss_oid_equal(name1->gn_type, GSS_C_NT_ANONYMOUS) ||
		    gss_oid_equal(name2->gn_type, GSS_C_NT_ANONYMOUS) ||
		    !gss_oid_equal(name1->gn_type, name2->gn_type)) {
			*name_equal = 0;
		} else if (name1->gn_value.length != name2->gn_value.length ||
		    memcmp(name1->gn_value.value, name2->gn_value.value,
			name1->gn_value.length) != 0) {
			*name_equal = 0;
		}
	} else {
		struct _gss_mechanism_name *mn1;
		struct _gss_mechanism_name *mn2;

		HEIM_TAILQ_FOREACH(mn1, &name1->gn_mn, gmn_link) {
			OM_uint32 major_status;

			major_status = _gss_find_mn(minor_status, name2,
						    mn1->gmn_mech_oid, &mn2);
			if (major_status == GSS_S_COMPLETE && mn2) {
				return (mn1->gmn_mech->gm_compare_name(
						minor_status,
						mn1->gmn_name,
						mn2->gmn_name,
						name_equal));
			}
		}
		HEIM_TAILQ_FOREACH(mn2, &name2->gn_mn, gmn_link) {
			OM_uint32 major_status;

			major_status = _gss_find_mn(minor_status, name1,
						    mn2->gmn_mech_oid, &mn1);
			if (major_status == GSS_S_COMPLETE && mn1) {
				return (mn2->gmn_mech->gm_compare_name(
						minor_status,
						mn2->gmn_name,
						mn1->gmn_name,
						name_equal));
			}
		}
		*name_equal = 0;
	}

	*minor_status = 0;
	return (GSS_S_COMPLETE);
}
