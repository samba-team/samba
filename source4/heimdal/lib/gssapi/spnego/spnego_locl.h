/*
 * Copyright (c) 2004, PADL Software Pty Ltd.
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
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $Id$ */

#ifndef SPNEGO_LOCL_H
#define SPNEGO_LOCL_H

#include <config.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include <roken.h>

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include <krb5.h>
#include <gssapi.h>
#include <gssapi_krb5.h>
#include <gssapi_spnego.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <heim_threads.h>
#include <heimqueue.h>
#include <asn1_err.h>

#include <gssapi_mech.h>

#include "spnego_asn1.h"
#include "negoex_locl.h"
#include "utils.h"
#include <der.h>

#include <heimbase.h>

#define ALLOC(X, N) (X) = calloc((N), sizeof(*(X)))

#define CHECK(ret, x) do { (ret) = (x); if (ret) goto fail; } while (0)

struct gssspnego_ctx_desc;
typedef struct gssspnego_ctx_desc *gssspnego_ctx;

typedef OM_uint32
(*gssspnego_initiator_state)(OM_uint32 * minor_status,
			     gss_const_cred_id_t cred,
			     gssspnego_ctx ctx,
			     gss_const_name_t name,
			     gss_const_OID mech_type,
			     OM_uint32 req_flags,
			     OM_uint32 time_req,
			     const gss_channel_bindings_t input_chan_bindings,
			     gss_const_buffer_t input_token,
			     gss_buffer_t output_token,
			     OM_uint32 * ret_flags,
			     OM_uint32 * time_rec);

struct gssspnego_ctx_desc {
	gss_buffer_desc		NegTokenInit_mech_types;
	gss_OID			preferred_mech_type;
	gss_OID			selected_mech_type;
	gss_OID			negotiated_mech_type;
	gss_ctx_id_t		negotiated_ctx_id;
	OM_uint32		mech_flags;
	OM_uint32		mech_time_rec;
	gss_name_t		mech_src_name;
	struct spnego_flags {
	    unsigned int		open : 1;
	    unsigned int		local : 1;
	    unsigned int		require_mic : 1;
	    unsigned int		peer_require_mic : 1;
	    unsigned int		sent_mic : 1;
	    unsigned int		verified_mic : 1;
	    unsigned int		safe_omit : 1;
	    unsigned int		maybe_open : 1;
	    unsigned int		seen_supported_mech : 1;
	} flags;
	HEIMDAL_MUTEX		ctx_id_mutex;

	gss_name_t		target_name;
	gssspnego_initiator_state   initiator_state;

	uint8_t			negoex_step;
	krb5_storage		*negoex_transcript;
	uint32_t		negoex_seqnum;
	conversation_id		negoex_conv_id;
	HEIM_TAILQ_HEAD(negoex_mech_list, negoex_auth_mech) negoex_mechs;
};

extern gss_OID_desc _gss_spnego_mskrb_mechanism_oid_desc;

struct gssspnego_optimistic_ctx {
    gssspnego_ctx spnegoctx;
    OM_uint32 req_flags;
    gss_name_t target_name;
    OM_uint32 time_req;
    gss_channel_bindings_t input_chan_bindings;
    /* out */
    gss_OID preferred_mech_type;
    gss_OID negotiated_mech_type;
    gss_buffer_desc optimistic_token;
    OM_uint32 optimistic_flags, optimistic_time_rec;
    gss_ctx_id_t gssctx;
    int complete;
    auth_scheme scheme;
};

#include "spnego-private.h"

static inline int
gssspnego_ctx_complete_p(gssspnego_ctx ctx)
{
    return ctx->flags.open &&
	    (ctx->flags.safe_omit || (ctx->flags.sent_mic && ctx->flags.verified_mic));
}

#endif /* SPNEGO_LOCL_H */
