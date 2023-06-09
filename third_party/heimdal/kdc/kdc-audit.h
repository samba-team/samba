/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $Id$ */

#ifndef HEIMDAL_KDC_KDC_AUDIT_H
#define HEIMDAL_KDC_KDC_AUDIT_H 1

/*
 * KDC auditing
 */

/* auth event type enumeration, currently for AS only */
#define KDC_AUTH_EVENT_INVALID			0   /* no event logged */
#define KDC_AUTH_EVENT_CLIENT_AUTHORIZED	1   /* all authn/authz checks passed */
#define KDC_AUTH_EVENT_CLIENT_UNKNOWN	        2   /* client unknown */
#define KDC_AUTH_EVENT_CLIENT_LOCKED_OUT	3   /* client locked out */
#define KDC_AUTH_EVENT_CLIENT_TIME_SKEW		4   /* client time skew */
#define KDC_AUTH_EVENT_WRONG_LONG_TERM_KEY	5   /* PA failed to validate long term key */
#define KDC_AUTH_EVENT_VALIDATED_LONG_TERM_KEY	6   /* PA validated long term key */
#define KDC_AUTH_EVENT_CLIENT_NAME_UNAUTHORIZED	7   /* couldn't map GSS/PKINIT name to principal */
#define KDC_AUTH_EVENT_PREAUTH_FAILED		8   /* generic PA failure */
#define KDC_AUTH_EVENT_PREAUTH_SUCCEEDED	9   /* generic (non-long term key) PA success */
#define KDC_AUTH_EVENT_HISTORIC_LONG_TERM_KEY	10  /* PA failed to validate current long term key, but historic */

/*
 * Audit keys to be queried using kdc_audit_getkv(). There are other keys
 * intended for logging that are not defined below; the constants below are
 * there to ease migration from the older auth_status HDB API.
 */

#define KDC_REQUEST_KV_AUTH_EVENT		"#auth_event"		/* heim_number_t */
#define KDC_REQUEST_KV_PA_NAME			"pa"			/* heim_string_t */
#define KDC_REQUEST_KV_PA_ETYPE			"pa-etype"		/* heim_number_t */
#define KDC_REQUEST_KV_PA_SUCCEEDED_KVNO	"pa-succeeded-kvno"	/* heim_number_t */
#define KDC_REQUEST_KV_PA_FAILED_KVNO		"pa-failed-kvno"	/* heim_number_t */
#define KDC_REQUEST_KV_GSS_INITIATOR		"gss_initiator"		/* heim_string_t */
#define KDC_REQUEST_KV_PKINIT_CLIENT_CERT	"pkinit_client_cert"	/* heim_string_t */
#define KDC_REQUEST_KV_PA_HISTORIC_KVNO		"pa-historic-kvno"	/* heim_number_t */

#endif /* HEIMDAL_KDC_KDC_AUDIT_H */
