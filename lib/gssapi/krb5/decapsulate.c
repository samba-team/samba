#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32
gssapi_krb5_verify_header(u_char **str,
			  size_t total_len,
			  u_char *type)
{
    size_t len, len_len, mech_len, foo;
    int e;
    u_char *p = *str;

    if (*p++ != 0x60)
	return GSS_S_DEFECTIVE_TOKEN;
    e = der_get_length (p, total_len - 1, &len, &len_len);
    if (e || 1 + len_len + len != total_len)
	abort ();
    p += len_len;
    if (*p++ != 0x06)
	return GSS_S_DEFECTIVE_TOKEN;
    e = der_get_length (p, total_len - 1 - len_len - 1,
			&mech_len, &foo);
    if (e)
	abort ();
    p += foo;
    if (mech_len != GSS_KRB5_MECHANISM->length)
	return GSS_S_BAD_MECH;
    if (memcmp(p,
	       GSS_KRB5_MECHANISM->elements,
	       GSS_KRB5_MECHANISM->length) != 0)
	return GSS_S_BAD_MECH;
    p += mech_len;
    if (memcmp (p, type, 2) != 0)
	return GSS_S_DEFECTIVE_TOKEN;
    p += 2;
    *str = p;
    return GSS_S_COMPLETE;
}

/*
 * Remove the GSS-API wrapping from `in_token' giving `out_data.
 * Does not copy data, so just free `in_token'.
 */

OM_uint32
gssapi_krb5_decapsulate(
			gss_buffer_t input_token_buffer,
			krb5_data *out_data,
			u_char *type
)
{
    u_char *p;
    OM_uint32 ret;

    p = input_token_buffer->value;
    ret = gssapi_krb5_verify_header(&p,
				    input_token_buffer->length,
				    type);
    if (ret)
	return ret;

    out_data->length = input_token_buffer->length -
	(p - (u_char *)input_token_buffer->value);
    out_data->data   = p;
    return GSS_S_COMPLETE;
}
