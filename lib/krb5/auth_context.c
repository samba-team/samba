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
    p->cksumtype = CKSUMTYPE_RSA_MD4; /* XXX - CKSUMTYPE_RSA_MD4_DES */;
    p->enctype   = ETYPE_DES_CBC_CRC;
    p->local_address = NULL;
    p->remote_address = NULL;
    *auth_context = p;
    return 0;
}

krb5_error_code
krb5_auth_con_free(krb5_context context,
		   krb5_auth_context auth_context)
{
    krb5_free_authenticator(context, &auth_context->authenticator);
    if(auth_context->local_address){
	free_HostAddress(auth_context->local_address);
	free(auth_context->local_address);
    }
    if(auth_context->remote_address){
	free_HostAddress(auth_context->remote_address);
	free(auth_context->remote_address);
    }
    free_EncryptionKey(&auth_context->key);
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
    if (local_addr) {
	if (auth_context->local_address)
	    krb5_free_address (context, auth_context->local_address);
	else
	    auth_context->local_address = malloc(sizeof(krb5_address));
	krb5_copy_address(context, local_addr, auth_context->local_address);
    }
    if (remote_addr) {
	if (auth_context->remote_address)
	    krb5_free_address (context, auth_context->remote_address);
	else
	    auth_context->remote_address = malloc(sizeof(krb5_address));
	krb5_copy_address(context, remote_addr, auth_context->remote_address);
    }
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
    krb5_copy_address(context,
		      auth_context->local_address,
		      *local_addr);

    if(*remote_addr)
	krb5_free_address (context, *remote_addr);
    *remote_addr = malloc (sizeof(**remote_addr));
    if (*remote_addr == NULL)
	return ENOMEM;
    krb5_copy_address(context,
		      auth_context->remote_address,
		      *remote_addr);
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
  (*keyblock)->keyvalue.length = 0;
  return krb5_data_copy (&(*keyblock)->keyvalue,
			 auth_context->key.keyvalue.data,
			 auth_context->key.keyvalue.length);
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
  (*keyblock)->keyvalue.length = 0;
  return krb5_data_copy (&(*keyblock)->keyvalue,
			 auth_context->local_subkey.keyvalue.data,
			 auth_context->local_subkey.keyvalue.length);
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
  (*keyblock)->keyvalue.length = 0;
  return krb5_data_copy (&(*keyblock)->keyvalue,
			 auth_context->remote_subkey.keyvalue.data,
			 auth_context->remote_subkey.keyvalue.length);
}

void
krb5_free_keyblock(krb5_context context,
		   krb5_keyblock *keyblock)
{
    memset(keyblock->keyvalue.data, 0, keyblock->keyvalue.length);
    krb5_data_free (&keyblock->keyvalue);
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
  *seqnumber = auth_context->local_seqnumber;
  return 0;
}

krb5_error_code
krb5_auth_setlocalseqnumber (krb5_context context,
			     krb5_auth_context auth_context,
			     int32_t seqnumber)
{
  auth_context->local_seqnumber = seqnumber;
  return 0;
}

krb5_error_code
krb5_auth_getremoteseqnumber(krb5_context context,
			     krb5_auth_context auth_context,
			     int32_t *seqnumber)
{
  *seqnumber = auth_context->remote_seqnumber;
  return 0;
}

krb5_error_code
krb5_auth_setremoteseqnumber (krb5_context context,
			      krb5_auth_context auth_context,
			      int32_t seqnumber)
{
  auth_context->remote_seqnumber = seqnumber;
  return 0;
}


krb5_error_code
krb5_auth_getauthenticator(krb5_context context,
			   krb5_auth_context auth_context,
			   krb5_authenticator *authenticator)
{
    *authenticator = malloc(sizeof(**authenticator));
    if (*authenticator == NULL)
	return ENOMEM;

    copy_Authenticator(auth_context->authenticator,
		       *authenticator);
    return 0;
}


void
krb5_free_authenticator(krb5_context context,
			krb5_authenticator *authenticator)
{
    free_Authenticator (*authenticator);
    free (*authenticator);
    *authenticator = NULL;
}


krb5_error_code
krb5_auth_initvector(krb5_context context,
		     krb5_auth_context auth_context)
{
    abort ();
}


krb5_error_code
krb5_set_initvector(krb5_context context,
		    krb5_auth_context auth_context,
		    krb5_pointer ivector)
{
    abort ();
}


krb5_error_code
krb5_set_rcache(krb5_context context,
		krb5_auth_context auth_context,
		krb5_rcache rcache)
{
    abort ();
}
