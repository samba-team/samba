#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32 gss_accept_sec_context
           (OM_uint32 * minor_status,
            gss_ctx_id_t * context_handle,
            const gss_cred_id_t acceptor_cred_handle,
            const gss_buffer_t input_token_buffer,
            const gss_channel_bindings_t input_chan_bindings,
            gss_name_t * src_name,
            gss_OID * mech_type,
            gss_buffer_t output_token,
            OM_uint32 * ret_flags,
            OM_uint32 * time_rec,
            gss_cred_id_t * delegated_cred_handle
           )
{
  krb5_error_code kret;
  OM_uint32 ret;
  krb5_data indata;
  krb5_flags ap_options;
  OM_uint32 flags;
  krb5_ticket *ticket;

  gssapi_krb5_init ();

  *context_handle = malloc(sizeof(**context_handle));
  if (*context_handle == NULL)
    return GSS_S_FAILURE;

  (*context_handle)->auth_context =  NULL;
  (*context_handle)->source = NULL;
  (*context_handle)->target = NULL;
  (*context_handle)->flags = 0;
  (*context_handle)->more_flags = 0;

  kret = krb5_auth_con_init (gssapi_krb5_context,
			     &(*context_handle)->auth_context);
  if (kret) {
    ret = GSS_S_FAILURE;
    goto failure;
  }

  ret = gssapi_krb5_decapsulate (input_token_buffer,
				 &indata,
				 "\x01\x00");
  if (ret)
    goto failure;

  kret = krb5_rd_req (gssapi_krb5_context,
		      &(*context_handle)->auth_context,
		      &indata,
		      /*server*/ NULL,	/* XXX */
		      NULL,
		      &ap_options,
		      &ticket);
  if (kret) {
    ret = GSS_S_FAILURE;
    goto failure;
  }

  kret = krb5_copy_principal (gssapi_krb5_context,
			      ticket->enc_part2.client,
			      &(*context_handle)->source);
  if (kret) {
    ret = GSS_S_FAILURE;
    goto failure;
  }

  if (src_name) {
    kret = krb5_copy_principal (gssapi_krb5_context,
				ticket->enc_part2.client,
				src_name);
    if (kret) {
      ret = GSS_S_FAILURE;
      goto failure;
    }
  }

  flags = 0;
  if (ap_options & AP_OPTS_MUTUAL_REQUIRED)
    flags |= GSS_C_MUTUAL_FLAG;
  flags |= GSS_C_CONF_FLAG;
  flags |= GSS_C_INTEG_FLAG;

  if (ret_flags)
    *ret_flags = flags;
  (*context_handle)->flags = flags;
  (*context_handle)->more_flags |= OPEN;

  if (mech_type)
    *mech_type = GSS_KRB5_MECHANISM;

  if (time_rec)
    *time_rec = GSS_C_INDEFINITE;

  if(flags & GSS_C_MUTUAL_FLAG) {
    krb5_data outbuf;

    kret = krb5_mk_rep (gssapi_krb5_context,
			&(*context_handle)->auth_context,
			&outbuf);
    if (kret) {
      krb5_data_free (&outbuf);
      ret = GSS_S_FAILURE;
      goto failure;
    }
    ret = gssapi_krb5_encapsulate (&outbuf,
				   output_token,
				   "\x02\x00");
    if (ret)
      goto failure;
  } else {
    output_token->length = 0;
  }

  return GSS_S_COMPLETE;

failure:
  krb5_auth_con_free (gssapi_krb5_context,
		      (*context_handle)->auth_context);
  if((*context_handle)->source)
    krb5_free_principal (gssapi_krb5_context,
			 (*context_handle)->source);
  if((*context_handle)->target)
    krb5_free_principal (gssapi_krb5_context,
			 (*context_handle)->target);
  free (*context_handle);
  *context_handle = GSS_C_NO_CONTEXT;
  return GSS_S_FAILURE;
}
