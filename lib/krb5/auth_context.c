#include "krb5_locl.h"

krb5_error_code
krb5_auth_con_init(krb5_context context,
		   krb5_auth_context **auth_context)
{
  krb5_auth_context *p;
  p = ALLOC(1, krb5_auth_context);;
  if(!p)
    return ENOMEM;
  memset(p, 0, sizeof(p));
  p->authenticator = ALLOC(1, krb5_authenticator);
  if (!p->authenticator)
    return ENOMEM;
  *auth_context = p;
  return 0;
}

krb5_error_code
krb5_auth_con_free(krb5_context context,
		   krb5_auth_context *auth_context,
		   krb5_flags flags)
{
  free (auth_context->authenticator);
  free (auth_context);
  return 0;
}

krb5_error_code
krb5_auth_con_setflags(krb5_context context,
		       krb5_auth_context *auth_context,
		       krb5_int32 flags)
{
}


krb5_error_code
krb5_auth_con_getflags(krb5_context context,
		       krb5_auth_context *auth_context,
		       krb5_int32 *flags)
{
}


krb5_error_code
krb5_auth_con_setaddrs(krb5_context context,
		       krb5_auth_context *auth_context,
		       krb5_address *local_addr,
		       krb5_address *remote_addr)
{
}


krb5_error_code
krb5_auth_con_getaddrs(krb5_context context,
		       krb5_auth_context *auth_context,
		       krb5_address **local_addr,
		       krb5_address **remote_addr)
{
}



krb5_error_code
krb5_auth_con_setuserkey(krb5_context context,
			 krb5_auth_context *auth_context,
			 krb5_keyblock *keyblock)
{
}


krb5_error_code
krb5_auth_con_getkey(krb5_context context,
		     krb5_auth_context *auth_context,
		     krb5_keyblock **keyblock)
{
}


/* ??? */
void
krb5_free_keyblock(krb5_keyblock *keyblock)
{
  
}

krb5_error_code
krb5_auth_setcksumtype(krb5_context context,
		       krb5_auth_context *auth_context,
		       krb5_cksumtype cksumtype)
{
}


krb5_error_code
krb5_auth_getlocalseqnumber(krb5_context context,
			    krb5_auth_context *auth_context,
			    krb5_int32 *seqnumber)
{
}


krb5_error_code
krb5_auth_getremoteseqnumber(krb5_context context,
			     krb5_auth_context *auth_context,
			     krb5_int32 *seqnumber)
{
}


krb5_error_code
krb5_auth_getauthenticator(krb5_context context,
			   krb5_auth_context *auth_context,
			   krb5_authenticator **authenticator)
{
}


void
krb5_free_authenticator(krb5_authenticator *authenticator)
{
}
 /* ??? */

krb5_error_code
krb5_auth_initvector(krb5_context context,
		     krb5_auth_context *auth_context)
{
}


krb5_error_code
krb5_set_initvector(krb5_context context,
		    krb5_auth_context *auth_context,
		    krb5_pointer ivector)
{
}


krb5_error_code
krb5_set_rcache(krb5_context context,
		krb5_auth_context *auth_context,
		krb5_rcache rcache)
{
}
