#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_auth_con_init(krb5_context context,
		   krb5_auth_context *auth_context)
{
    krb5_auth_context p;

    p = ALLOC(1, krb5_auth_context_data);;
    if(!p)
	return ENOMEM;
    memset(p, 0, sizeof(*p));
    p->authenticator = ALLOC(1, krb5_authenticator_data);
    if (!p->authenticator)
	return ENOMEM;
    p->flags = KRB5_AUTH_CONTEXT_DO_TIME;
    p->cksumtype = CKSUMTYPE_RSA_MD4_DES;
    *auth_context = p;
    return 0;
}

krb5_error_code
krb5_auth_con_free(krb5_context context,
		   krb5_auth_context auth_context)
{
    free (auth_context->authenticator);
    free (auth_context);
    return 0;
}

krb5_error_code
krb5_auth_con_setflags(krb5_context context,
		       krb5_auth_context auth_context,
		       int32_t flags)
{
    auth_context->flags = flags;
    return 0;
}


krb5_error_code
krb5_auth_con_getflags(krb5_context context,
		       krb5_auth_context auth_context,
		       int32_t *flags)
{
    *flags = auth_context->flags;
    return 0;
}


krb5_error_code
krb5_auth_con_setaddrs(krb5_context context,
		       krb5_auth_context auth_context,
		       krb5_address *local_addr,
		       krb5_address *remote_addr)
{
    auth_context->local_address.type = local_addr->type;
    krb5_data_copy (&auth_context->local_address.address,
		    local_addr->address.data,
		    local_addr->address.length);
    auth_context->remote_address.type = remote_addr->type;
    krb5_data_copy (&auth_context->remote_address.address,
		    remote_addr->address.data,
		    remote_addr->address.length);
    return 0;
}


krb5_error_code
krb5_auth_con_getaddrs(krb5_context context,
		       krb5_auth_context auth_context,
		       krb5_address **local_addr,
		       krb5_address **remote_addr)
{
    krb5_error_code ret;

    if(*local_addr)
	krb5_free_address (context, *local_addr);
    *local_addr = malloc (sizeof(**local_addr));
    if (*local_addr == NULL)
	return ENOMEM;
    (*local_addr)->type = auth_context->local_address.type;
    ret = krb5_data_copy (&(*local_addr)->address,
			  auth_context->local_address.address.data,
			  auth_context->local_address.address.length);
    if (ret)
	return ret;

    if(*remote_addr)
	krb5_free_address (context, *remote_addr);
    *remote_addr = malloc (sizeof(**remote_addr));
    if (*remote_addr == NULL)
	return ENOMEM;
    (*remote_addr)->type = auth_context->remote_address.type;
    ret = krb5_data_copy (&(*remote_addr)->address,
			  auth_context->remote_address.address.data,
			  auth_context->remote_address.address.length);
    if (ret)
	return ret;

    return 0;
}

krb5_error_code
krb5_auth_con_setuserkey(krb5_context context,
			 krb5_auth_context auth_context,
			 krb5_keyblock *keyblock)
{
    abort ();
}


krb5_error_code
krb5_auth_con_getkey(krb5_context context,
		     krb5_auth_context auth_context,
		     krb5_keyblock **keyblock)
{
  *keyblock = malloc(sizeof(**keyblock));
  if (*keyblock == NULL)
    return ENOMEM;
  (*keyblock)->keytype = auth_context->key.keytype;
  (*keyblock)->contents.length = 0;
  return krb5_data_copy (&(*keyblock)->contents,
			 auth_context->key.contents.data,
			 auth_context->key.contents.length);
}

krb5_error_code
krb5_auth_con_getlocalsubkey(krb5_context context,
			     krb5_auth_context auth_context,
			     krb5_keyblock **keyblock)
{
  *keyblock = malloc(sizeof(**keyblock));
  if (*keyblock == NULL)
    return ENOMEM;
  (*keyblock)->keytype = auth_context->local_subkey.keytype;
  (*keyblock)->contents.length = 0;
  return krb5_data_copy (&(*keyblock)->contents,
			 auth_context->local_subkey.contents.data,
			 auth_context->local_subkey.contents.length);
}

krb5_error_code
krb5_auth_con_getremotesubkey(krb5_context context,
			      krb5_auth_context auth_context,
			      krb5_keyblock **keyblock)
{
  *keyblock = malloc(sizeof(**keyblock));
  if (*keyblock == NULL)
    return ENOMEM;
  (*keyblock)->keytype = auth_context->remote_subkey.keytype;
  (*keyblock)->contents.length = 0;
  return krb5_data_copy (&(*keyblock)->contents,
			 auth_context->remote_subkey.contents.data,
			 auth_context->remote_subkey.contents.length);
}

void
krb5_free_keyblock(krb5_context context,
		   krb5_keyblock *keyblock)
{
  krb5_data_free (&keyblock->contents);
  free (keyblock);
}

krb5_error_code
krb5_auth_setcksumtype(krb5_context context,
		       krb5_auth_context auth_context,
		       krb5_cksumtype cksumtype)
{
    auth_context->cksumtype = cksumtype;
    return 0;
}

krb5_error_code
krb5_auth_getcksumtype(krb5_context context,
		       krb5_auth_context auth_context,
		       krb5_cksumtype *cksumtype)
{
    *cksumtype = auth_context->cksumtype;
    return 0;
}

krb5_error_code
krb5_auth_getlocalseqnumber(krb5_context context,
			    krb5_auth_context auth_context,
			    int32_t *seqnumber)
{
}


krb5_error_code
krb5_auth_getremoteseqnumber(krb5_context context,
			     krb5_auth_context auth_context,
			     int32_t *seqnumber)
{
}


krb5_error_code
krb5_auth_getauthenticator(krb5_context context,
			   krb5_auth_context auth_context,
			   krb5_authenticator *authenticator)
{
    *authenticator = malloc(sizeof(**authenticator));
    if (*authenticator == NULL)
	return ENOMEM;
    (*authenticator)->vno = auth_context->authenticator->vno;
    krb5_copy_principal (context,
			 auth_context->authenticator->cname,
			 &(*authenticator)->cname);
    (*authenticator)->cusec = auth_context->authenticator->cusec;
    (*authenticator)->ctime = auth_context->authenticator->ctime;
    (*authenticator)->seq_number = auth_context->authenticator->seq_number; /* XXX */
    return 0;
}


void
krb5_free_authenticator(krb5_context context,
			krb5_authenticator *authenticator)
{
    krb5_free_principal (context, (*authenticator)->cname);
    free (*authenticator);
    *authenticator = NULL;
}


krb5_error_code
krb5_auth_initvector(krb5_context context,
		     krb5_auth_context auth_context)
{
}


krb5_error_code
krb5_set_initvector(krb5_context context,
		    krb5_auth_context auth_context,
		    krb5_pointer ivector)
{
}


krb5_error_code
krb5_set_rcache(krb5_context context,
		krb5_auth_context auth_context,
		krb5_rcache rcache)
{
}
