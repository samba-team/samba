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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/param.h>

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include <gssapi_spnego.h>
#include <gssapi.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <heim_threads.h>
#include "spnego_asn1.h"
#include <der.h>
#include <asn1_err.h>

#include <gssapi_mech.h>

#define ALLOC(X, N) (X) = calloc((N), sizeof(*(X)))

typedef struct {
	gss_cred_id_t		negotiated_cred_id;
} *gssspnego_cred;

typedef struct {
	MechTypeList		initiator_mech_types;
	gss_OID			preferred_mech_type;
	gss_OID			negotiated_mech_type;
	gss_ctx_id_t		negotiated_ctx_id;
	OM_uint32		mech_flags;
	OM_uint32		mech_time_rec;
	gss_name_t		mech_src_name;
	gss_cred_id_t		delegated_cred_id;
	int			open : 1;
	int			local : 1;
	int			require_mic : 1;
	int			verified_mic : 1;
	HEIMDAL_MUTEX		ctx_id_mutex;
} *gssspnego_ctx;

OM_uint32
_gss_spnego_encode_response(OM_uint32 *, const NegTokenResp *,
			    gss_buffer_t, u_char **);
OM_uint32
_gss_spnego_indicate_mechtypelist (OM_uint32 *, int,
				   const gssspnego_cred cred_handle,
				   MechTypeList *,
				   gss_OID *preferred_mech);
OM_uint32 _gss_spnego_alloc_sec_context (OM_uint32 *,
					 gss_ctx_id_t *);

/*
 * NB: caller must acquire ctx_id_mutex before
 * calling _gss_spnego_delete_sec_context()
 */
OM_uint32 _gss_spnego_delete_sec_context (OM_uint32 *, gss_ctx_id_t *, gss_buffer_t);
OM_uint32 _gss_spnego_require_mechlist_mic(OM_uint32 *, gssspnego_ctx, int *);
OM_uint32 gss_spnego_internal_release_oid(OM_uint32 *minor_status, gss_OID *OID);
int _gss_spnego_add_mech_type(gss_OID, int, MechTypeList *);
OM_uint32 _gss_spnego_select_mech(OM_uint32 *, MechType *, gss_OID *);
OM_uint32 _gss_spnego_alloc_cred(OM_uint32 *, gss_cred_id_t, gss_cred_id_t *);
OM_uint32 _gss_spnego_release_cred(OM_uint32 *, gss_cred_id_t *);

OM_uint32 _gss_spnego_supported_mechs(OM_uint32 *, gss_OID_set *);


/*
 * Finally, function prototypes for the GSS-API routines.
 */

OM_uint32 gss_spnego_acquire_cred
           (OM_uint32 * /*minor_status*/,
            const gss_name_t /*desired_name*/,
            OM_uint32 /*time_req*/,
            const gss_OID_set /*desired_mechs*/,
            gss_cred_usage_t /*cred_usage*/,
            gss_cred_id_t * /*output_cred_handle*/,
            gss_OID_set * /*actual_mechs*/,
            OM_uint32 * /*time_rec*/
           );

OM_uint32 gss_spnego_release_cred
           (OM_uint32 * /*minor_status*/,
            gss_cred_id_t * /*cred_handle*/
           );

OM_uint32 gss_spnego_init_sec_context
           (OM_uint32 * /*minor_status*/,
            const gss_cred_id_t /*initiator_cred_handle*/,
            gss_ctx_id_t * /*context_handle*/,
            const gss_name_t /*target_name*/,
            const gss_OID /*mech_type*/,
            OM_uint32 /*req_flags*/,
            OM_uint32 /*time_req*/,
            const gss_channel_bindings_t /*input_chan_bindings*/,
            const gss_buffer_t /*input_token*/,
            gss_OID * /*actual_mech_type*/,
            gss_buffer_t /*output_token*/,
            OM_uint32 * /*ret_flags*/,
            OM_uint32 * /*time_rec*/
           );

OM_uint32 gss_spnego_accept_sec_context
           (OM_uint32 * /*minor_status*/,
            gss_ctx_id_t * /*context_handle*/,
            const gss_cred_id_t /*acceptor_cred_handle*/,
            const gss_buffer_t /*input_token_buffer*/,
            const gss_channel_bindings_t /*input_chan_bindings*/,
            gss_name_t * /*src_name*/,
            gss_OID * /*mech_type*/,
            gss_buffer_t /*output_token*/,
            OM_uint32 * /*ret_flags*/,
            OM_uint32 * /*time_rec*/,
            gss_cred_id_t * /*delegated_cred_handle*/
           );

OM_uint32 gss_spnego_process_context_token
           (OM_uint32 * /*minor_status*/,
            const gss_ctx_id_t /*context_handle*/,
            const gss_buffer_t /*token_buffer*/
           );

OM_uint32 gss_spnego_delete_sec_context
           (OM_uint32 * /*minor_status*/,
            gss_ctx_id_t * /*context_handle*/,
            gss_buffer_t /*output_token*/
           );

OM_uint32 gss_spnego_context_time
           (OM_uint32 * /*minor_status*/,
            const gss_ctx_id_t /*context_handle*/,
            OM_uint32 * /*time_rec*/
           );

OM_uint32 gss_spnego_get_mic
           (OM_uint32 * /*minor_status*/,
            const gss_ctx_id_t /*context_handle*/,
            gss_qop_t /*qop_req*/,
            const gss_buffer_t /*message_buffer*/,
            gss_buffer_t /*message_token*/
           );

OM_uint32 gss_spnego_verify_mic
           (OM_uint32 * /*minor_status*/,
            const gss_ctx_id_t /*context_handle*/,
            const gss_buffer_t /*message_buffer*/,
            const gss_buffer_t /*token_buffer*/,
            gss_qop_t * /*qop_state*/
           );

OM_uint32 gss_spnego_wrap
           (OM_uint32 * /*minor_status*/,
            const gss_ctx_id_t /*context_handle*/,
            int /*conf_req_flag*/,
            gss_qop_t /*qop_req*/,
            const gss_buffer_t /*input_message_buffer*/,
            int * /*conf_state*/,
            gss_buffer_t /*output_message_buffer*/
           );

OM_uint32 gss_spnego_unwrap
           (OM_uint32 * /*minor_status*/,
            const gss_ctx_id_t /*context_handle*/,
            const gss_buffer_t /*input_message_buffer*/,
            gss_buffer_t /*output_message_buffer*/,
            int * /*conf_state*/,
            gss_qop_t * /*qop_state*/
           );

OM_uint32 gss_spnego_display_status
           (OM_uint32 * /*minor_status*/,
            OM_uint32 /*status_value*/,
            int /*status_type*/,
            const gss_OID /*mech_type*/,
            OM_uint32 * /*message_context*/,
            gss_buffer_t /*status_string*/
           );

OM_uint32 gss_spnego_inquire_names_for_mech (
            OM_uint32 * minor_status,
            const gss_OID mechanism,
            gss_OID_set * name_types
	   );

OM_uint32 gss_spnego_compare_name
           (OM_uint32 * /*minor_status*/,
            const gss_name_t /*name1*/,
            const gss_name_t /*name2*/,
            int * /*name_equal*/
           );

OM_uint32 gss_spnego_display_name
           (OM_uint32 * /*minor_status*/,
            const gss_name_t /*input_name*/,
            gss_buffer_t /*output_name_buffer*/,
            gss_OID * /*output_name_type*/
           );

OM_uint32 gss_spnego_import_name
           (OM_uint32 * /*minor_status*/,
            const gss_buffer_t /*input_name_buffer*/,
            const gss_OID /*input_name_type*/,
            gss_name_t * /*output_name*/
           );

OM_uint32 gss_spnego_export_name
           (OM_uint32  * /*minor_status*/,
            const gss_name_t /*input_name*/,
            gss_buffer_t /*exported_name*/
           );

OM_uint32 gss_spnego_release_name
           (OM_uint32 * /*minor_status*/,
            gss_name_t * /*input_name*/
           );

OM_uint32 gss_spnego_release_buffer
           (OM_uint32 * /*minor_status*/,
            gss_buffer_t /*buffer*/
           );

OM_uint32 gss_spnego_release_oid_set
           (OM_uint32 * /*minor_status*/,
            gss_OID_set * /*set*/
           );

OM_uint32 gss_spnego_inquire_cred
           (OM_uint32 * /*minor_status*/,
            const gss_cred_id_t /*cred_handle*/,
            gss_name_t * /*name*/,
            OM_uint32 * /*lifetime*/,
            gss_cred_usage_t * /*cred_usage*/,
            gss_OID_set * /*mechanisms*/
           );

OM_uint32 gss_spnego_inquire_context (
            OM_uint32 * /*minor_status*/,
            const gss_ctx_id_t /*context_handle*/,
            gss_name_t * /*src_name*/,
            gss_name_t * /*targ_name*/,
            OM_uint32 * /*lifetime_rec*/,
            gss_OID * /*mech_type*/,
            OM_uint32 * /*ctx_flags*/,
            int * /*locally_initiated*/,
            int * /*open_context*/
           );

OM_uint32 gss_spnego_wrap_size_limit (
            OM_uint32 * /*minor_status*/,
            const gss_ctx_id_t /*context_handle*/,
            int /*conf_req_flag*/,
            gss_qop_t /*qop_req*/,
            OM_uint32 /*req_output_size*/,
            OM_uint32 * /*max_input_size*/
           );

OM_uint32 gss_spnego_add_cred (
            OM_uint32 * /*minor_status*/,
            const gss_cred_id_t /*input_cred_handle*/,
            const gss_name_t /*desired_name*/,
            const gss_OID /*desired_mech*/,
            gss_cred_usage_t /*cred_usage*/,
            OM_uint32 /*initiator_time_req*/,
            OM_uint32 /*acceptor_time_req*/,
            gss_cred_id_t * /*output_cred_handle*/,
            gss_OID_set * /*actual_mechs*/,
            OM_uint32 * /*initiator_time_rec*/,
            OM_uint32 * /*acceptor_time_rec*/
           );

OM_uint32 gss_spnego_inquire_cred_by_mech (
            OM_uint32 * /*minor_status*/,
            const gss_cred_id_t /*cred_handle*/,
            const gss_OID /*mech_type*/,
            gss_name_t * /*name*/,
            OM_uint32 * /*initiator_lifetime*/,
            OM_uint32 * /*acceptor_lifetime*/,
            gss_cred_usage_t * /*cred_usage*/
           );

OM_uint32 gss_spnego_export_sec_context (
            OM_uint32 * /*minor_status*/,
            gss_ctx_id_t * /*context_handle*/,
            gss_buffer_t /*interprocess_token*/
           );

OM_uint32 gss_spnego_import_sec_context (
            OM_uint32 * /*minor_status*/,
            const gss_buffer_t /*interprocess_token*/,
            gss_ctx_id_t * /*context_handle*/
           );

OM_uint32 gss_spnego_create_empty_oid_set (
            OM_uint32 * /*minor_status*/,
            gss_OID_set * /*oid_set*/
           );

OM_uint32 gss_spnego_add_oid_set_member (
            OM_uint32 * /*minor_status*/,
            const gss_OID /*member_oid*/,
            gss_OID_set * /*oid_set*/
           );

OM_uint32 gss_spnego_test_oid_set_member (
            OM_uint32 * /*minor_status*/,
            const gss_OID /*member*/,
            const gss_OID_set /*set*/,
            int * /*present*/
           );

OM_uint32 gss_spnego_inquire_mechs_for_name (
            OM_uint32 * /*minor_status*/,
            const gss_name_t /*input_name*/,
            gss_OID_set * /*mech_types*/
           );

OM_uint32 gss_spnego_duplicate_name (
            OM_uint32 * /*minor_status*/,
            const gss_name_t /*src_name*/,
            gss_name_t * /*dest_name*/
           );

OM_uint32 gss_spnego_canonicalize_name (
            OM_uint32 * minor_status,
            const gss_name_t src_name,
            const gss_OID mech_type,
            gss_name_t * dest_name
           );

/*
 * The following routines are obsolete variants of gss_get_mic,
 * gss_verify_mic, gss_wrap and gss_unwrap.  They should be
 * provided by GSSAPI V2 implementations for backwards
 * compatibility with V1 applications.  Distinct entrypoints
 * (as opposed to #defines) should be provided, both to allow
 * GSSAPI V1 applications to link against GSSAPI V2 implementations,
 * and to retain the slight parameter type differences between the
 * obsolete versions of these routines and their current forms.
 */

OM_uint32 gss_spnego_sign
           (OM_uint32 * /*minor_status*/,
            gss_ctx_id_t /*context_handle*/,
            int /*qop_req*/,
            gss_buffer_t /*message_buffer*/,
            gss_buffer_t /*message_token*/
           );

OM_uint32 gss_spnego_verify
           (OM_uint32 * /*minor_status*/,
            gss_ctx_id_t /*context_handle*/,
            gss_buffer_t /*message_buffer*/,
            gss_buffer_t /*token_buffer*/,
            int * /*qop_state*/
           );

OM_uint32 gss_spnego_seal
           (OM_uint32 * /*minor_status*/,
            gss_ctx_id_t /*context_handle*/,
            int /*conf_req_flag*/,
            int /*qop_req*/,
            gss_buffer_t /*input_message_buffer*/,
            int * /*conf_state*/,
            gss_buffer_t /*output_message_buffer*/
           );

OM_uint32 gss_spnego_unseal
           (OM_uint32 * /*minor_status*/,
            gss_ctx_id_t /*context_handle*/,
            gss_buffer_t /*input_message_buffer*/,
            gss_buffer_t /*output_message_buffer*/,
            int * /*conf_state*/,
            int * /*qop_state*/
           );

#if 0
OM_uint32 gss_spnego_unwrap_ex
           (OM_uint32 * /*minor_status*/,
            const gss_ctx_id_t /*context_handle*/,
	    const gss_buffer_t /*token_header_buffer*/,
	    const gss_buffer_t /*associated_data_buffer*/,
	    const gss_buffer_t /*input_message_buffer*/,
	    gss_buffer_t /*output_message_buffer*/,
	    int * /*conf_state*/,
	    gss_qop_t * /*qop_state*/);

OM_uint32 gss_spnego_wrap_ex
           (OM_uint32 * /*minor_status*/,
            const gss_ctx_id_t /*context_handle*/,
            int /*conf_req_flag*/,
            gss_qop_t /*qop_req*/,
            const gss_buffer_t /*associated_data_buffer*/,
            const gss_buffer_t /*input_message_buffer*/,
            int * /*conf_state*/,
            gss_buffer_t /*output_token_buffer*/,
            gss_buffer_t /*output_message_buffer*/
	   );

OM_uint32 gss_spnego_complete_auth_token
           (OM_uint32 * /*minor_status*/,
            const gss_ctx_id_t /*context_handle*/,
	    gss_buffer_t /*input_message_buffer*/);
#endif

OM_uint32 gss_spnego_inquire_sec_context_by_oid
           (OM_uint32 * /*minor_status*/,
            const gss_ctx_id_t /*context_handle*/,
            const gss_OID /*desired_object*/,
            gss_buffer_set_t */*data_set*/);

OM_uint32 gss_spnego_inquire_cred_by_oid
           (OM_uint32 * /*minor_status*/,
            const gss_cred_id_t /*cred_handle*/,
            const gss_OID /*desired_object*/,
            gss_buffer_set_t */*data_set*/);

OM_uint32 gss_spnego_set_sec_context_option
           (OM_uint32 * /*minor_status*/,
            gss_ctx_id_t * /*cred_handle*/,
            const gss_OID /*desired_object*/,
            const gss_buffer_t /*value*/);

#endif /* SPNEGO_LOCL_H */
