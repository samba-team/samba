/* $Id$ */

#ifndef GSSAPI_LOCL_H
#define GSSAPI_LOCL_H

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <gssapi.h>

#include <krb5.h>
#include <des.h>
#include <krb5_locl.h>

extern krb5_context gssapi_krb5_context;

void gssapi_krb5_init (void);

krb5_error_code
gssapi_krb5_create_8003_checksum (
		      const gss_channel_bindings_t input_chan_bindings,
		      OM_uint32 flags,
		      Checksum *result);

OM_uint32
gssapi_krb5_encapsulate(
			krb5_data *in_data,
			gss_buffer_t output_token,
			u_char *type);

OM_uint32
gssapi_krb5_decapsulate(
			gss_buffer_t input_token_buffer,
			krb5_data *out_data,
			u_char *type);

void
gssapi_krb5_encap_length (size_t data_len,
			  size_t *len,
			  size_t *total_len);

u_char *
gssapi_krb5_make_header (u_char *p,
			 size_t len,
			 u_char *type);

OM_uint32
gssapi_krb5_verify_header(u_char **str,
			  size_t total_len,
			  u_char *type);

#endif
